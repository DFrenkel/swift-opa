import AST
import Foundation
import SwiftASN1
import X509

// Implements OPA's `crypto.x509.*` and `crypto.parse_private_keys` builtins.
//
// These parse X.509 certificates, certificate signing requests, key pairs and
// RSA private keys. Certificate and CSR parsing is done with swift-certificates;
// RSA private keys are decoded directly from their PKCS#1 ASN.1 structure with
// swift-asn1 so we can emit the JWK representation OPA produces.
//
// The objects returned here are a compliance-driven subset of the fields Go's
// `crypto/x509` emits.
extension BuiltinFuncs {
    // MARK: - Certificates

    static func x509ParseCertificates(ctx: BuiltinContext, args: [AST.RegoValue]) throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }
        guard case .string(let input) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "certs", got: args[0].typeName, want: "string")
        }

        let objects = try parseCertificateObjects(from: input)
        return .array(objects)
    }

    static func x509ParseAndVerifyCertificates(ctx: BuiltinContext, args: [AST.RegoValue]) throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }
        guard case .string(let input) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "certs", got: args[0].typeName, want: "string")
        }

        return try verifyCertificateChain(from: input, now: ctx.timestamp)
    }

    static func x509ParseAndVerifyCertificatesWithOptions(ctx: BuiltinContext, args: [AST.RegoValue]) throws
        -> AST.RegoValue
    {
        guard args.count == 2 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 2)
        }
        guard case .string(let input) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "certs", got: args[0].typeName, want: "string")
        }
        guard case .object = args[1] else {
            throw BuiltinError.argumentTypeMismatch(arg: "options", got: args[1].typeName, want: "object")
        }

        // TODO: verification options are not yet honored.
        return try verifyCertificateChain(from: input, now: ctx.timestamp)
    }

    static func x509ParseCertificateRequest(ctx: BuiltinContext, args: [AST.RegoValue]) throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }
        guard case .string(let input) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "csr", got: args[0].typeName, want: "string")
        }

        let der = try singleDER(from: input, pemDiscriminator: "CERTIFICATE REQUEST")
        let csr: CertificateSigningRequest
        do {
            csr = try CertificateSigningRequest(derEncoded: der)
        } catch {
            throw BuiltinError.evalError(msg: "asn1: structure error: \(error)")
        }

        return csrToRegoValue(csr)
    }

    static func x509ParseKeyPair(ctx: BuiltinContext, args: [AST.RegoValue]) throws -> AST.RegoValue {
        guard args.count == 2 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 2)
        }
        guard case .string(let certInput) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "cert", got: args[0].typeName, want: "string")
        }
        guard case .string(let keyInput) = args[1] else {
            throw BuiltinError.argumentTypeMismatch(arg: "key", got: args[1].typeName, want: "string")
        }

        let certBlocks = try certificateDERBlocks(from: certInput)
        // Validate the certificate parses; the key is decoded to confirm it is present.
        for block in certBlocks {
            do {
                _ = try Certificate(derEncoded: block)
            } catch {
                throw BuiltinError.evalError(msg: "x509: malformed certificate: \(error)")
            }
        }
        _ = try singleDER(from: keyInput, pemDiscriminator: "PRIVATE KEY")

        let derStrings = certBlocks.map { AST.RegoValue.string(Data($0).base64EncodedString()) }
        return .object([.string("Certificate"): .array(derStrings)])
    }

    // MARK: - Private keys

    static func x509ParseRSAPrivateKey(ctx: BuiltinContext, args: [AST.RegoValue]) throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }
        guard case .string(let input) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "pem", got: args[0].typeName, want: "string")
        }

        let der = try singleDER(from: input, pemDiscriminator: "RSA PRIVATE KEY")
        return try rsaPrivateKeyJWK(fromPKCS1: der)
    }

    static func parsePrivateKeys(ctx: BuiltinContext, args: [AST.RegoValue]) throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }
        guard case .string(let input) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "keys", got: args[0].typeName, want: "string")
        }

        // Empty input yields null, matching OPA.
        if input.isEmpty {
            return .null
        }

        // Gather candidate PEM blocks either from the raw string or its base64 decoding.
        var blocks = extractPEMBlocks(input)
        if blocks.isEmpty, let data = Data(base64Encoded: input),
            let decoded = String(bytes: [UInt8](data), encoding: .utf8)
        {
            blocks = extractPEMBlocks(decoded)
        }

        let keyBlocks = blocks.filter { $0.type.contains("PRIVATE KEY") }
        let keys: [AST.RegoValue] = keyBlocks.map { block in
            if block.type == "RSA PRIVATE KEY", let jwk = try? rsaPrivateKeyJWK(fromPKCS1: block.der) {
                return jwk
            }
            return .object([.string("kty"): .string(block.type)])
        }
        return .array(keys)
    }
}

// MARK: - Decoding helpers

extension BuiltinFuncs {
    /// Parses one or more certificates from a PEM string, base64-encoded PEM, or
    /// base64-encoded (optionally concatenated) DER.
    static func parseCertificates(from input: String) throws -> [Certificate] {
        let blocks = try certificateDERBlocks(from: input)
        var certs: [Certificate] = []
        certs.reserveCapacity(blocks.count)
        for block in blocks {
            do {
                certs.append(try Certificate(derEncoded: block))
            } catch {
                throw BuiltinError.evalError(msg: "x509: malformed certificate: \(error)")
            }
        }
        return certs
    }

    /// Builds the certificate objects for `crypto.x509.parse_certificates`.
    ///
    /// swift-certificates is used when it can parse the certificate. It eagerly
    /// validates the public key and rejects, for example, RSA keys under 2048
    /// bits, whereas Go's `crypto/x509` (and therefore OPA) parses permissively.
    /// For those certificates we fall back to reading the fields we expose
    /// directly from the DER with swift-asn1.
    fileprivate static func parseCertificateObjects(from input: String) throws -> [AST.RegoValue] {
        let blocks = try certificateDERBlocks(from: input)
        var objects: [AST.RegoValue] = []
        objects.reserveCapacity(blocks.count)
        for block in blocks {
            if let cert = try? Certificate(derEncoded: block) {
                objects.append(certificateToRegoValue(cert))
            } else if let fields = permissiveCertificateFields(block) {
                objects.append(
                    certificateObject(commonName: fields.commonName ?? "", dns: fields.dns, uris: fields.uris))
            } else {
                throw BuiltinError.evalError(msg: "x509: malformed certificate")
            }
        }
        return objects
    }

    /// Returns the DER byte blocks for one or more certificates encoded in `input`.
    fileprivate static func certificateDERBlocks(from input: String) throws -> [[UInt8]] {
        if input.hasPrefix("-----BEGIN") {
            return try pemDERBlocks(input, discriminator: "CERTIFICATE")
        }
        guard let data = Data(base64Encoded: input) else {
            throw BuiltinError.evalError(msg: "illegal base64 data")
        }
        let bytes = [UInt8](data)
        if let str = String(bytes: bytes, encoding: .utf8), str.hasPrefix("-----BEGIN") {
            return try pemDERBlocks(str, discriminator: "CERTIFICATE")
        }
        return try splitDERBlocks(bytes)
    }

    /// Returns the DER bytes for a single object (certificate, CSR or key) encoded
    /// as PEM, base64-encoded PEM, or base64-encoded DER.
    fileprivate static func singleDER(from input: String, pemDiscriminator: String) throws -> [UInt8] {
        if input.hasPrefix("-----BEGIN") {
            return try firstPEMDERBlock(input, preferred: pemDiscriminator)
        }
        guard let data = Data(base64Encoded: input) else {
            throw BuiltinError.evalError(msg: "illegal base64 data")
        }
        let bytes = [UInt8](data)
        if let str = String(bytes: bytes, encoding: .utf8), str.hasPrefix("-----BEGIN") {
            return try firstPEMDERBlock(str, preferred: pemDiscriminator)
        }
        return bytes
    }

    private static func pemDERBlocks(_ pem: String, discriminator: String) throws -> [[UInt8]] {
        let matching = extractPEMBlocks(pem).filter { $0.type == discriminator }
        guard !matching.isEmpty else {
            throw BuiltinError.evalError(msg: "no PEM \(discriminator) blocks found")
        }
        return matching.map { $0.der }
    }

    private static func firstPEMDERBlock(_ pem: String, preferred discriminator: String) throws -> [UInt8] {
        let blocks = extractPEMBlocks(pem)
        if let block = blocks.first(where: { $0.type == discriminator }) ?? blocks.first {
            return block.der
        }
        throw BuiltinError.evalError(msg: "no PEM blocks found")
    }

    /// Extracts PEM blocks leniently. Go's `pem.Decode` tolerates arbitrary
    /// base64 line lengths, whereas swift-asn1's `PEMDocument` requires RFC
    /// 64-character wrapping and rejects single-line bodies; several OPA
    /// compliance fixtures use unwrapped bodies, so we scan the blocks ourselves.
    static func extractPEMBlocks(_ pem: String) -> [(type: String, der: [UInt8])] {
        var blocks: [(String, [UInt8])] = []
        var currentType: String?
        var body = ""

        for rawLine in pem.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----BEGIN ") && line.hasSuffix("-----") {
                currentType = String(line.dropFirst("-----BEGIN ".count).dropLast("-----".count))
                body = ""
            } else if line.hasPrefix("-----END ") && line.hasSuffix("-----") {
                if let type = currentType, let data = Data(base64Encoded: body) {
                    blocks.append((type, [UInt8](data)))
                }
                currentType = nil
                body = ""
            } else if currentType != nil {
                body += line
            }
        }
        return blocks
    }

    /// Splits a buffer of one or more concatenated DER TLV structures into their
    /// individual byte ranges by reading each element's length header.
    private static func splitDERBlocks(_ bytes: [UInt8]) throws -> [[UInt8]] {
        var blocks: [[UInt8]] = []
        var i = 0
        let n = bytes.count
        while i < n {
            let start = i
            i += 1  // tag byte (single-byte tags only, sufficient for SEQUENCE)
            guard i < n else {
                throw BuiltinError.evalError(msg: "x509: malformed certificate")
            }
            let lengthByte = bytes[i]
            i += 1

            var length: Int
            if lengthByte & 0x80 == 0 {
                length = Int(lengthByte)
            } else {
                let numLengthBytes = Int(lengthByte & 0x7f)
                guard numLengthBytes > 0, numLengthBytes <= 4, i + numLengthBytes <= n else {
                    throw BuiltinError.evalError(msg: "x509: malformed certificate")
                }
                length = 0
                for _ in 0..<numLengthBytes {
                    length = (length << 8) | Int(bytes[i])
                    i += 1
                }
            }

            let end = i + length
            guard end <= n else {
                throw BuiltinError.evalError(msg: "x509: malformed certificate")
            }
            blocks.append(Array(bytes[start..<end]))
            i = end
        }
        guard !blocks.isEmpty else {
            throw BuiltinError.evalError(msg: "x509: malformed certificate")
        }
        return blocks
    }
}

// MARK: - Certificate to RegoValue

extension BuiltinFuncs {
    /// Builds the compliance-driven subset object for a certificate.
    fileprivate static func certificateToRegoValue(_ cert: Certificate) -> AST.RegoValue {
        let (dnsNames, uriStrings) = subjectAltNames(cert)
        return certificateObject(commonName: commonName(cert.subject) ?? "", dns: dnsNames, uris: uriStrings)
    }

    /// Shared object shape for a parsed certificate, used by both the
    /// swift-certificates path and the permissive swift-asn1 fallback.
    fileprivate static func certificateObject(commonName: String, dns: [String], uris: [String]) -> AST.RegoValue {
        return .object([
            .string("Subject"): .object([
                .string("CommonName"): .string(commonName)
            ]),
            .string("DNSNames"): namesArrayOrNull(dns),
            .string("URIStrings"): namesArrayOrNull(uris),
        ])
    }

    fileprivate static func csrToRegoValue(_ csr: CertificateSigningRequest) -> AST.RegoValue {
        return .object([
            .string("Subject"): .object([
                .string("CommonName"): .string(commonName(csr.subject) ?? "")
            ])
        ])
    }

    /// Extracts the CommonName from a distinguished name, if present.
    fileprivate static func commonName(_ dn: DistinguishedName) -> String? {
        for rdn in dn {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                if let value = String(attribute.value) {
                    return value
                }
            }
        }
        return nil
    }

    /// Returns the DNS names and URI strings from a certificate's Subject
    /// Alternative Name extension.
    fileprivate static func subjectAltNames(_ cert: Certificate) -> (dns: [String], uris: [String]) {
        var dns: [String] = []
        var uris: [String] = []
        if let san = try? cert.extensions.subjectAlternativeNames {
            for name in san {
                switch name {
                case .dnsName(let value):
                    dns.append(value)
                case .uniformResourceIdentifier(let value):
                    uris.append(value)
                default:
                    break
                }
            }
        }
        return (dns, uris)
    }

    /// OPA (via Go's json.Marshal) emits an absent string slice as null rather
    /// than an empty array.
    fileprivate static func namesArrayOrNull(_ names: [String]) -> AST.RegoValue {
        names.isEmpty ? .null : .array(names.map { .string($0) })
    }
}

// MARK: - Chain verification

extension BuiltinFuncs {
    /// Verifies that the supplied certificates form a chain and returns
    /// `[valid, [certs...]]` with the chain ordered leaf-to-root, matching OPA.
    fileprivate static func verifyCertificateChain(from input: String, now: Date) throws -> AST.RegoValue {
        let certs = try parseCertificates(from: input)
        guard let leaf = certs.last else {
            return .array([.boolean(false), .array([])])
        }

        var chain: [Certificate] = [leaf]
        var current = leaf
        var valid = true

        while current.issuer != current.subject {
            guard
                let issuer = certs.first(where: {
                    $0.subject == current.issuer && $0.publicKey.isValidSignature(current.signature, for: current)
                })
            else {
                valid = false
                break
            }
            chain.append(issuer)
            current = issuer
            // Guard against cycles in a malformed input set.
            if chain.count > certs.count {
                valid = false
                break
            }
        }

        // A complete chain ends at a self-signed root with a valid self-signature.
        if valid, current.issuer == current.subject,
            !current.publicKey.isValidSignature(current.signature, for: current)
        {
            valid = false
        }

        // Every certificate in the chain must be within its validity window.
        for cert in chain where now < cert.notValidBefore || now > cert.notValidAfter {
            valid = false
        }

        let certValues = chain.map { certificateToRegoValue($0) }
        return .array([.boolean(valid), .array(certValues)])
    }
}

// MARK: - RSA private key (PKCS#1) to JWK

extension BuiltinFuncs {
    /// Decodes a PKCS#1 `RSAPrivateKey` DER structure into a JWK object.
    ///
    /// `RSAPrivateKey ::= SEQUENCE { version, modulus (n), publicExponent (e),
    /// privateExponent (d), prime1 (p), prime2 (q), exponent1 (dp),
    /// exponent2 (dq), coefficient (qi) }`.
    fileprivate static func rsaPrivateKeyJWK(fromPKCS1 der: [UInt8]) throws -> AST.RegoValue {
        do {
            let root = try DER.parse(der)
            guard case .constructed(let sequence) = root.content else {
                throw BuiltinError.evalError(msg: "asn1: structure error: expected SEQUENCE")
            }

            var iterator = sequence.makeIterator()
            // Skip the version INTEGER.
            guard iterator.next() != nil else {
                throw BuiltinError.evalError(msg: "asn1: structure error: missing version")
            }

            func nextInteger() throws -> [UInt8] {
                guard let node = iterator.next() else {
                    throw BuiltinError.evalError(msg: "asn1: structure error: missing RSA field")
                }
                return Array(try ArraySlice<UInt8>(derEncoded: node))
            }

            let n = try nextInteger()
            let e = try nextInteger()
            let d = try nextInteger()
            let p = try nextInteger()
            let q = try nextInteger()
            let dp = try nextInteger()
            let dq = try nextInteger()
            let qi = try nextInteger()

            return .object([
                .string("kty"): .string("RSA"),
                .string("n"): .string(base64URLNoPad(n)),
                .string("e"): .string(base64URLNoPad(e)),
                .string("d"): .string(base64URLNoPad(d)),
                .string("p"): .string(base64URLNoPad(p)),
                .string("q"): .string(base64URLNoPad(q)),
                .string("dp"): .string(base64URLNoPad(dp)),
                .string("dq"): .string(base64URLNoPad(dq)),
                .string("qi"): .string(base64URLNoPad(qi)),
            ])
        } catch let error as RegoError {
            throw error
        } catch {
            throw BuiltinError.evalError(msg: "asn1: structure error: \(error)")
        }
    }

    /// Base64url encoding without padding, matching JWK member encoding.
    fileprivate static func base64URLNoPad(_ bytes: [UInt8]) -> String {
        var s = Data(bytes).base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }
}

// MARK: - Permissive certificate field extraction

extension BuiltinFuncs {
    /// Reads the Subject CommonName and Subject Alternative Name DNS/URI entries
    /// directly from a certificate's DER, without validating the public key.
    ///
    /// Used as a fallback for certificates swift-certificates refuses to parse
    /// (notably RSA keys under 2048 bits), so that `crypto.x509.parse_certificates`
    /// remains as permissive as Go's `crypto/x509`. Returns nil when the bytes are
    /// not a well-formed certificate.
    fileprivate static func permissiveCertificateFields(_ der: [UInt8]) -> (
        commonName: String?, dns: [String], uris: [String]
    )? {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        guard let certificate = try? DER.parse(der),
            case .constructed(let certFields) = certificate.content,
            let tbs = Array(certFields).first,
            case .constructed(let tbsSequence) = tbs.content
        else {
            return nil
        }

        // TBSCertificate ::= SEQUENCE {
        //   version [0] EXPLICIT DEFAULT v1, serialNumber, signature, issuer,
        //   validity, subject, subjectPublicKeyInfo, ..., extensions [3] EXPLICIT }
        let children = Array(tbsSequence)
        // Skip the optional explicit [0] version wrapper.
        let base = (children.first.map { isContextTag($0, 0) } ?? false) ? 1 : 0
        let subjectIndex = base + 4
        guard children.count > subjectIndex else {
            return nil
        }

        let commonName = commonNameFromName(children[subjectIndex])

        var dns: [String] = []
        var uris: [String] = []
        for node in children[(subjectIndex + 1)...] where isContextTag(node, 3) {
            (dns, uris) = subjectAltNamesFromExtensions(node)
            break
        }

        return (commonName, dns, uris)
    }

    /// Extracts the CommonName from a `Name` (RDNSequence) ASN.1 node.
    private static func commonNameFromName(_ name: ASN1Node) -> String? {
        // Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
        guard case .constructed(let rdns) = name.content else {
            return nil
        }
        for rdn in rdns {
            guard case .constructed(let attributes) = rdn.content else {
                continue
            }
            for attribute in attributes {
                guard case .constructed(let pair) = attribute.content else {
                    continue
                }
                let parts = Array(pair)
                guard parts.count >= 2,
                    let oid = try? ASN1ObjectIdentifier(derEncoded: parts[0]),
                    oid == [2, 5, 4, 3]  // id-at-commonName
                else {
                    continue
                }
                return directoryString(parts[1])
            }
        }
        return nil
    }

    /// Parses the SAN extension out of the explicit `[3] Extensions` node.
    private static func subjectAltNamesFromExtensions(_ extensionsWrapper: ASN1Node) -> (dns: [String], uris: [String])
    {
        // [3] EXPLICIT wraps Extensions ::= SEQUENCE OF Extension
        guard case .constructed(let wrapper) = extensionsWrapper.content,
            let extensionsSeq = Array(wrapper).first,
            case .constructed(let extensions) = extensionsSeq.content
        else {
            return ([], [])
        }

        for ext in extensions {
            // Extension ::= SEQUENCE { extnID OID, critical BOOL DEFAULT FALSE, extnValue OCTET STRING }
            guard case .constructed(let fields) = ext.content else {
                continue
            }
            var iterator = fields.makeIterator()
            guard let oidNode = iterator.next(),
                let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode),
                oid == [2, 5, 29, 17]  // id-ce-subjectAltName
            else {
                continue
            }
            guard var valueNode = iterator.next() else {
                continue
            }
            // Skip the optional critical BOOLEAN to reach the OCTET STRING.
            if valueNode.identifier == .boolean {
                guard let next = iterator.next() else { continue }
                valueNode = next
            }
            guard case .primitive(let octets) = valueNode.content else {
                continue
            }
            return generalNames(fromDER: Array(octets))
        }
        return ([], [])
    }

    /// Parses `GeneralNames` DER, collecting dNSName ([2]) and URI ([6]) entries.
    private static func generalNames(fromDER der: [UInt8]) -> (dns: [String], uris: [String]) {
        guard let sequence = try? DER.parse(der),
            case .constructed(let names) = sequence.content
        else {
            return ([], [])
        }
        var dns: [String] = []
        var uris: [String] = []
        for name in names {
            guard case .primitive(let bytes) = name.content,
                let value = String(bytes: bytes, encoding: .utf8)
            else {
                continue
            }
            if isContextTag(name, 2) {
                dns.append(value)
            } else if isContextTag(name, 6) {
                uris.append(value)
            }
        }
        return (dns, uris)
    }

    /// Decodes a DirectoryString-style ATV value (PrintableString, UTF8String,
    /// IA5String, etc.) as a Swift string.
    private static func directoryString(_ node: ASN1Node) -> String? {
        guard case .primitive(let bytes) = node.content else {
            return nil
        }
        return String(bytes: bytes, encoding: .utf8)
    }

    /// True when a node carries a context-specific tag with the given number.
    private static func isContextTag(_ node: ASN1Node, _ number: UInt) -> Bool {
        return node.identifier.tagClass == .contextSpecific && node.identifier.tagNumber == number
    }
}
