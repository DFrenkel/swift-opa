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
