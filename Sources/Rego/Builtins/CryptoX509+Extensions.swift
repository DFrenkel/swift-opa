import AST
import Foundation
import SwiftASN1
import X509

// Extracts the extension-derived certificate fields OPA emits. Everything is
// computed from the raw extension bytes (oid, critical, value) so the
// swift-certificates path and the permissive DER path share one implementation.
extension BuiltinFuncs {
    /// A certificate extension reduced to the pieces both parse paths can supply.
    struct X509Ext {
        let oid: [UInt]
        let critical: Bool
        let value: [UInt8]  // raw DER of the extension's value
    }

    static func normalizedExtensions(_ exts: Certificate.Extensions) -> [X509Ext] {
        exts.map { X509Ext(oid: $0.oid.oidComponents, critical: $0.critical, value: Array($0.value)) }
    }

    /// Go's `Extensions` list: `[{Critical, Id:[oid ints], Value: base64}]`.
    static func extensionList(_ exts: [X509Ext]) -> AST.RegoValue {
        guard !exts.isEmpty else { return .null }
        return .array(
            exts.map { ext in
                .object([
                    .string("Critical"): .boolean(ext.critical),
                    .string("Id"): oidArray(ext.oid),
                    .string("Value"): .string(Data(ext.value).base64EncodedString()),
                ])
            })
    }

    /// KeyUsage bitmask from the KeyUsage extension (OID 2.5.29.15).
    static func keyUsageValue(_ exts: [X509Ext]) -> Int {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 15] }),
            let node = try? DER.parse(ext.value),
            case .primitive(let bits) = node.content
        else { return 0 }
        return goKeyUsageValue(fromBitString: Array(bits))
    }

    /// Extended key usage (OID 2.5.29.37): known usages as Go ints, plus any
    /// unrecognized usage OIDs.
    static func extKeyUsageValues(_ exts: [X509Ext]) -> (known: [Int], unknown: [[UInt]]) {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 37] }),
            let node = try? DER.parse(ext.value),
            case .constructed(let seq) = node.content
        else { return ([], []) }
        var known: [Int] = []
        var unknown: [[UInt]] = []
        for oidNode in seq {
            guard let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode) else { continue }
            if let value = goExtKeyUsage(oid) {
                known.append(value)
            } else {
                unknown.append(oid.oidComponents)
            }
        }
        return (known, unknown)
    }

    /// Basic constraints (OID 2.5.29.19). `valid` reflects whether the extension
    /// was present; `maxPathLen` is -1 when no path length is set, matching Go.
    static func basicConstraints(_ exts: [X509Ext]) -> (
        valid: Bool, isCA: Bool, maxPathLen: Int, maxPathLenZero: Bool
    ) {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 19] }),
            let node = try? DER.parse(ext.value),
            case .constructed(let seq) = node.content
        else { return (false, false, -1, false) }
        var isCA = false
        var maxPathLen = -1
        var maxPathLenZero = false
        for child in seq {
            if child.identifier == .boolean, case .primitive(let b) = child.content {
                isCA = (b.first ?? 0) != 0
            } else if let intBytes = try? Array(ArraySlice<UInt8>(derEncoded: child)) {
                maxPathLen = intBytes.reduce(0) { $0 * 256 + Int($1) }
                maxPathLenZero = maxPathLen == 0
            }
        }
        return (true, isCA, maxPathLen, maxPathLenZero)
    }

    /// Subject key identifier bytes (OID 2.5.29.14).
    static func subjectKeyID(_ exts: [X509Ext]) -> [UInt8] {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 14] }),
            let node = try? DER.parse(ext.value),
            case .primitive(let bytes) = node.content
        else { return [] }
        return Array(bytes)
    }

    /// Authority key identifier bytes: the [0] keyIdentifier of the AKI
    /// extension (OID 2.5.29.35).
    static func authorityKeyID(_ exts: [X509Ext]) -> [UInt8] {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 35] }),
            let node = try? DER.parse(ext.value),
            case .constructed(let seq) = node.content
        else { return [] }
        for child in seq
        where child.identifier.tagClass == .contextSpecific && child.identifier.tagNumber == 0 {
            if case .primitive(let bytes) = child.content {
                return Array(bytes)
            }
        }
        return []
    }

    /// OCSP responder and CA-issuer URLs from the authority information access
    /// extension (OID 1.3.6.1.5.5.7.1.1).
    static func accessInfo(_ exts: [X509Ext]) -> (ocsp: [String], caIssuers: [String]) {
        guard let ext = exts.first(where: { $0.oid == [1, 3, 6, 1, 5, 5, 7, 1, 1] }),
            let node = try? DER.parse(ext.value),
            case .constructed(let seq) = node.content
        else { return ([], []) }
        var ocsp: [String] = []
        var caIssuers: [String] = []
        for desc in seq {
            guard case .constructed(let pair) = desc.content else { continue }
            let items = Array(pair)
            guard items.count >= 2,
                let method = try? ASN1ObjectIdentifier(derEncoded: items[0]),
                let uri = contextString(items[1], tag: 6)
            else { continue }
            if method.oidComponents == [1, 3, 6, 1, 5, 5, 7, 48, 1] {
                ocsp.append(uri)
            } else if method.oidComponents == [1, 3, 6, 1, 5, 5, 7, 48, 2] {
                caIssuers.append(uri)
            }
        }
        return (ocsp, caIssuers)
    }

    /// CRL distribution point URLs (OID 2.5.29.31). Collects every URI
    /// (context tag 6) nested within the extension.
    static func crlDistributionPoints(_ exts: [X509Ext]) -> [String] {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 31] }),
            let node = try? DER.parse(ext.value)
        else { return [] }
        var uris: [String] = []
        collectContextURIs(node, into: &uris)
        return uris
    }

    /// Certificate policy OIDs (OID 2.5.29.32).
    static func policyIdentifiers(_ exts: [X509Ext]) -> [[UInt]] {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 32] }),
            let node = try? DER.parse(ext.value),
            case .constructed(let seq) = node.content
        else { return [] }
        var oids: [[UInt]] = []
        for policy in seq {
            guard case .constructed(let fields) = policy.content,
                let idNode = Array(fields).first,
                let oid = try? ASN1ObjectIdentifier(derEncoded: idNode)
            else { continue }
            oids.append(oid.oidComponents)
        }
        return oids
    }

    /// Subject alternative names (OID 2.5.29.17), split by general-name kind.
    static func subjectAltNames(_ exts: [X509Ext]) -> (
        dns: [String], email: [String], ip: [String], uris: [String]
    ) {
        guard let ext = exts.first(where: { $0.oid == [2, 5, 29, 17] }),
            let node = try? DER.parse(ext.value),
            case .constructed(let names) = node.content
        else { return ([], [], [], []) }
        var dns: [String] = []
        var email: [String] = []
        var ip: [String] = []
        var uris: [String] = []
        for name in names {
            guard case .primitive(let bytes) = name.content,
                name.identifier.tagClass == .contextSpecific
            else { continue }
            switch name.identifier.tagNumber {
            case 1: email.append(String(decoding: bytes, as: UTF8.self))
            case 2: dns.append(String(decoding: bytes, as: UTF8.self))
            case 6: uris.append(String(decoding: bytes, as: UTF8.self))
            case 7: ip.append(formatIPAddress(Array(bytes)))
            default: break
            }
        }
        return (dns, email, ip, uris)
    }

    // MARK: - Helpers

    static func oidArray(_ oid: [UInt]) -> AST.RegoValue {
        .array(oid.map { .number(RegoNumber(int: Int64($0))) })
    }

    /// Reads a context-specific tagged primitive as a UTF-8 string.
    private static func contextString(_ node: ASN1Node, tag: UInt) -> String? {
        guard node.identifier.tagClass == .contextSpecific, node.identifier.tagNumber == tag,
            case .primitive(let bytes) = node.content
        else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Recursively collects every context-tag-6 (URI) primitive under a node.
    private static func collectContextURIs(_ node: ASN1Node, into uris: inout [String]) {
        switch node.content {
        case .primitive(let bytes):
            if node.identifier.tagClass == .contextSpecific, node.identifier.tagNumber == 6 {
                uris.append(String(decoding: bytes, as: UTF8.self))
            }
        case .constructed(let children):
            for child in children {
                collectContextURIs(child, into: &uris)
            }
        }
    }

    /// Formats raw IP bytes as Go's net.IP text form (dotted IPv4 or colon IPv6).
    private static func formatIPAddress(_ bytes: [UInt8]) -> String {
        if bytes.count == 4 {
            return bytes.map { String($0) }.joined(separator: ".")
        }
        if bytes.count == 16 {
            var parts: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                parts.append(String(format: "%x", Int(bytes[i]) << 8 | Int(bytes[i + 1])))
            }
            return parts.joined(separator: ":")
        }
        return Data(bytes).base64EncodedString()
    }
}
