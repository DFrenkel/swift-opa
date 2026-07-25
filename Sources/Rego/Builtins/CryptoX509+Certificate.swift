import AST
import Foundation
import SwiftASN1
import X509

// Assembles the full Go `x509.Certificate` JSON object OPA emits. A `CertFields`
// bag carries the per-certificate source data so both parse paths (the
// swift-certificates path here and the permissive DER path) build the identical
// object through `certificateObject`.
extension BuiltinFuncs {
    struct CertFields {
        var version: Int
        var serialNumber: [UInt8]  // raw big-endian magnitude
        var signatureAlgorithm: Int
        var signatureBytes: [UInt8]
        var notBefore: Date
        var notAfter: Date
        var subject: AST.RegoValue  // pkix.Name object
        var issuer: AST.RegoValue  // pkix.Name object
        var publicKeyAlgorithm: Int
        var publicKey: AST.RegoValue
        var extensions: [X509Ext]
        var raw: [UInt8]
    }

    /// Builds the certificate object. Extension-derived fields are computed here
    /// so both parse paths share one implementation.
    static func certificateObject(_ f: CertFields) -> AST.RegoValue {
        let eku = extKeyUsageValues(f.extensions)
        let bc = basicConstraints(f.extensions)
        let access = accessInfo(f.extensions)
        let san = subjectAltNames(f.extensions)
        let skid = subjectKeyID(f.extensions)
        let akid = authorityKeyID(f.extensions)
        let policyOIDs = policyIdentifiers(f.extensions)

        return .object([
            .string("Raw"): .string(Data(f.raw).base64EncodedString()),
            .string("Version"): regoInt(f.version),
            .string("SerialNumber"): .string(decimalString(fromBigEndianBytes: f.serialNumber)),
            .string("SignatureAlgorithm"): regoInt(f.signatureAlgorithm),
            .string("Signature"): .string(Data(f.signatureBytes).base64EncodedString()),
            .string("PublicKeyAlgorithm"): regoInt(f.publicKeyAlgorithm),
            .string("PublicKey"): f.publicKey,
            .string("NotBefore"): .string(rfc3339(f.notBefore)),
            .string("NotAfter"): .string(rfc3339(f.notAfter)),
            .string("Subject"): f.subject,
            .string("Issuer"): f.issuer,
            .string("KeyUsage"): regoInt(keyUsageValue(f.extensions)),
            .string("ExtKeyUsage"): intsOrNull(eku.known),
            .string("UnknownExtKeyUsage"): eku.unknown.isEmpty
                ? .null : .array(eku.unknown.map { oidArray($0) }),
            .string("BasicConstraintsValid"): .boolean(bc.valid),
            .string("IsCA"): .boolean(bc.isCA),
            .string("MaxPathLen"): regoInt(bc.maxPathLen),
            .string("MaxPathLenZero"): .boolean(bc.maxPathLenZero),
            .string("SubjectKeyId"): bytesOrNull(skid),
            .string("AuthorityKeyId"): bytesOrNull(akid),
            .string("OCSPServer"): namesArrayOrNull(access.ocsp),
            .string("IssuingCertificateURL"): namesArrayOrNull(access.caIssuers),
            .string("CRLDistributionPoints"): namesArrayOrNull(crlDistributionPoints(f.extensions)),
            .string("DNSNames"): namesArrayOrNull(san.dns),
            .string("EmailAddresses"): namesArrayOrNull(san.email),
            .string("IPAddresses"): namesArrayOrNull(san.ip),
            .string("URIs"): .null,  // TODO: emit Go url.URL objects for URI SANs
            .string("URIStrings"): namesArrayOrNull(san.uris),
            .string("PolicyIdentifiers"): policyOIDs.isEmpty
                ? .null : .array(policyOIDs.map { oidArray($0) }),
            .string("Policies"): namesArrayOrNull(policyOIDs.map { dottedOID($0) }),
            .string("Extensions"): extensionList(f.extensions),
            .string("ExtraExtensions"): .null,
            .string("UnhandledCriticalExtensions"): .null,
            // Name constraints and policy-inhibit fields are not parsed this
            // round; OPA leaves them at Go's zero values for certificates that
            // omit them, which covers the common case.
            .string("PermittedDNSDomainsCritical"): .boolean(false),
            .string("PermittedDNSDomains"): .null,
            .string("ExcludedDNSDomains"): .null,
            .string("PermittedIPRanges"): .null,
            .string("ExcludedIPRanges"): .null,
            .string("PermittedEmailAddresses"): .null,
            .string("ExcludedEmailAddresses"): .null,
            .string("PermittedURIDomains"): .null,
            .string("ExcludedURIDomains"): .null,
            .string("PolicyMappings"): .null,
            .string("InhibitAnyPolicy"): regoInt(0),
            .string("InhibitAnyPolicyZero"): .boolean(false),
            .string("InhibitPolicyMapping"): regoInt(0),
            .string("InhibitPolicyMappingZero"): .boolean(false),
            .string("RequireExplicitPolicy"): regoInt(0),
            .string("RequireExplicitPolicyZero"): .boolean(false),
        ])
    }

    static func certFields(fromSwiftCert cert: Certificate, der: [UInt8]) -> CertFields {
        var publicKeyAlgorithm = 0
        var publicKey: AST.RegoValue = .null
        var serializer = DER.Serializer()
        if (try? serializer.serialize(cert.publicKey)) != nil,
            let obj = publicKeyObject(fromSPKIDer: serializer.serializedBytes)
        {
            publicKeyAlgorithm = obj.algorithm
            publicKey = obj.key
        }

        let version: Int
        if cert.version == .v1 {
            version = 1
        } else if cert.version == .v3 {
            version = 3
        } else {
            version = 2
        }

        return CertFields(
            version: version,
            serialNumber: Array(cert.serialNumber.bytes),
            signatureAlgorithm: goSignatureAlgorithm(cert.signatureAlgorithm),
            signatureBytes: signatureBytes(fromCertDER: der),
            notBefore: cert.notValidBefore,
            notAfter: cert.notValidAfter,
            subject: nameObject(cert.subject),
            issuer: nameObject(cert.issuer),
            publicKeyAlgorithm: publicKeyAlgorithm,
            publicKey: publicKey,
            extensions: normalizedExtensions(cert.extensions),
            raw: der
        )
    }

    /// The signatureValue BIT STRING of a certificate: the third element of the
    /// Certificate SEQUENCE, minus its unused-bits count byte.
    static func signatureBytes(fromCertDER der: [UInt8]) -> [UInt8] {
        guard let root = try? DER.parse(der), case .constructed(let seq) = root.content else { return [] }
        let nodes = Array(seq)
        guard nodes.count >= 3, case .primitive(let bits) = nodes[2].content else { return [] }
        return Array(bits.dropFirst())
    }

    // MARK: - Permissive DER path

    /// Builds `CertFields` for certificates swift-certificates refuses to
    /// construct (notably RSA keys under 2048 bits). Reads the TBSCertificate
    /// straight from the DER. Because big integers are string-encoded from raw
    /// bytes, reading the SubjectPublicKeyInfo here is not blocked by the
    /// key-size rejection, so this path can still emit PublicKey.
    static func certFields(fromDER der: [UInt8]) -> CertFields? {
        guard let root = try? DER.parse(der), case .constructed(let certSeq) = root.content else { return nil }
        let certNodes = Array(certSeq)
        guard certNodes.count >= 3, case .constructed(let tbsSeq) = certNodes[0].content else { return nil }
        let tbs = Array(tbsSeq)
        var idx = 0

        // Optional [0] EXPLICIT version, DEFAULT v1.
        var version = 1
        if let first = tbs.first, first.identifier.tagClass == .contextSpecific, first.identifier.tagNumber == 0 {
            if case .constructed(let wrapper) = first.content, let vNode = Array(wrapper).first,
                let vBytes = try? Array(ArraySlice<UInt8>(derEncoded: vNode))
            {
                version = vBytes.reduce(0) { $0 * 256 + Int($1) } + 1
            }
            idx = 1
        }

        guard tbs.count > idx, let serial = try? Array(ArraySlice<UInt8>(derEncoded: tbs[idx])) else { return nil }
        idx += 1

        guard tbs.count > idx, case .constructed(let sigAlgSeq) = tbs[idx].content,
            let sigOIDNode = Array(sigAlgSeq).first,
            let sigOID = try? ASN1ObjectIdentifier(derEncoded: sigOIDNode)
        else { return nil }
        let signatureAlgorithm = goSignatureAlgorithm(oid: sigOID)
        idx += 1

        guard tbs.count > idx, let issuer = try? DistinguishedName(derEncoded: tbs[idx]) else { return nil }
        idx += 1

        guard tbs.count > idx, case .constructed(let validitySeq) = tbs[idx].content else { return nil }
        let validity = Array(validitySeq)
        guard validity.count >= 2,
            let notBefore = parseASN1Time(validity[0]), let notAfter = parseASN1Time(validity[1])
        else { return nil }
        idx += 1

        guard tbs.count > idx, let subject = try? DistinguishedName(derEncoded: tbs[idx]) else { return nil }
        idx += 1

        guard tbs.count > idx else { return nil }
        var publicKeyAlgorithm = 0
        var publicKey: AST.RegoValue = .null
        if let obj = publicKeyObject(fromSPKINode: tbs[idx]) {
            publicKeyAlgorithm = obj.algorithm
            publicKey = obj.key
        }
        idx += 1

        var extensions: [X509Ext] = []
        for node in tbs[idx...]
        where node.identifier.tagClass == .contextSpecific && node.identifier.tagNumber == 3 {
            extensions = parseExtensions(fromExplicit: node)
            break
        }

        return CertFields(
            version: version,
            serialNumber: serial,
            signatureAlgorithm: signatureAlgorithm,
            signatureBytes: signatureBytes(fromCertDER: der),
            notBefore: notBefore,
            notAfter: notAfter,
            subject: nameObject(subject),
            issuer: nameObject(issuer),
            publicKeyAlgorithm: publicKeyAlgorithm,
            publicKey: publicKey,
            extensions: extensions,
            raw: der
        )
    }

    /// Parses the `[3] EXPLICIT Extensions` node into normalized extensions.
    private static func parseExtensions(fromExplicit node: ASN1Node) -> [X509Ext] {
        guard case .constructed(let wrapper) = node.content,
            let seq = Array(wrapper).first,
            case .constructed(let exts) = seq.content
        else { return [] }
        var result: [X509Ext] = []
        for ext in exts {
            guard case .constructed(let fields) = ext.content else { continue }
            var iterator = fields.makeIterator()
            guard let oidNode = iterator.next(),
                let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode),
                var next = iterator.next()
            else { continue }
            var critical = false
            if next.identifier == .boolean {
                if case .primitive(let b) = next.content { critical = (b.first ?? 0) != 0 }
                guard let after = iterator.next() else { continue }
                next = after
            }
            guard case .primitive(let octets) = next.content else { continue }
            result.append(X509Ext(oid: oid.oidComponents, critical: critical, value: Array(octets)))
        }
        return result
    }

    /// Parses an ASN.1 UTCTime or GeneralizedTime (Zulu form) into a Date.
    private static func parseASN1Time(_ node: ASN1Node) -> Date? {
        guard case .primitive(let bytes) = node.content else { return nil }
        var text = String(decoding: bytes, as: UTF8.self)
        guard text.hasSuffix("Z") else { return nil }
        text.removeLast()
        let digits = Array(text)
        func num(_ lower: Int, _ upper: Int) -> Int? {
            guard upper <= digits.count else { return nil }
            return Int(String(digits[lower..<upper]))
        }

        var comps = DateComponents()
        if digits.count == 12 {  // UTCTime: YYMMDDHHMMSS
            guard let yy = num(0, 2), let mo = num(2, 4), let dd = num(4, 6),
                let hh = num(6, 8), let mi = num(8, 10), let ss = num(10, 12)
            else { return nil }
            comps.year = yy < 50 ? 2000 + yy : 1900 + yy
            comps.month = mo; comps.day = dd; comps.hour = hh; comps.minute = mi; comps.second = ss
        } else if digits.count == 14 {  // GeneralizedTime: YYYYMMDDHHMMSS
            guard let yyyy = num(0, 4), let mo = num(4, 6), let dd = num(6, 8),
                let hh = num(8, 10), let mi = num(10, 12), let ss = num(12, 14)
            else { return nil }
            comps.year = yyyy; comps.month = mo; comps.day = dd
            comps.hour = hh; comps.minute = mi; comps.second = ss
        } else {
            return nil
        }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: comps)
    }

    // MARK: - Small encoders

    static func regoInt(_ value: Int) -> AST.RegoValue {
        .number(RegoNumber(int: Int64(value)))
    }

    static func bytesOrNull(_ bytes: [UInt8]) -> AST.RegoValue {
        bytes.isEmpty ? .null : .string(Data(bytes).base64EncodedString())
    }

    static func intsOrNull(_ values: [Int]) -> AST.RegoValue {
        values.isEmpty ? .null : .array(values.map { regoInt($0) })
    }

    static func dottedOID(_ oid: [UInt]) -> String {
        oid.map { String($0) }.joined(separator: ".")
    }

    /// Formats a Date as Go's RFC3339 encoding for UTC times (e.g.
    /// `2014-01-29T13:27:43Z`).
    static func rfc3339(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }
}
