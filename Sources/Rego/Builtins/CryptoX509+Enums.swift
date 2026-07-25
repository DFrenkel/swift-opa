import SwiftASN1
import X509

// Go crypto/x509 integer enum values. OPA emits these enums as ints (it
// json.Marshals the Go struct), so we reproduce Go's constants exactly.
extension BuiltinFuncs {
    /// Maps a swift-certificates signature algorithm to Go's
    /// `x509.SignatureAlgorithm` integer. Unknown algorithms map to 0.
    static func goSignatureAlgorithm(_ alg: Certificate.SignatureAlgorithm) -> Int {
        switch alg {
        case .sha1WithRSAEncryption: return 3
        case .sha256WithRSAEncryption: return 4
        case .sha384WithRSAEncryption: return 5
        case .sha512WithRSAEncryption: return 6
        case .ecdsaWithSHA256: return 10
        case .ecdsaWithSHA384: return 11
        case .ecdsaWithSHA512: return 12
        case .ed25519: return 16
        default: return 0  // UnknownSignatureAlgorithm
        }
    }

    /// Maps a signature-algorithm OID to Go's `x509.SignatureAlgorithm`
    /// integer. Used by the permissive DER path, which reads the OID directly.
    static func goSignatureAlgorithm(oid: ASN1ObjectIdentifier) -> Int {
        return goSignatureAlgorithms[oid] ?? 0
    }

    /// Maps a public-key algorithm OID to Go's `x509.PublicKeyAlgorithm`
    /// integer. Unknown OIDs map to 0.
    static func goPublicKeyAlgorithm(_ oid: ASN1ObjectIdentifier) -> Int {
        return goPublicKeyAlgorithms[oid] ?? 0
    }

    /// Maps an extended-key-usage OID to Go's `x509.ExtKeyUsage` integer.
    /// Returns nil for OIDs Go does not recognize; the caller records those in
    /// `UnknownExtKeyUsage`.
    static func goExtKeyUsage(_ oid: ASN1ObjectIdentifier) -> Int? {
        return goExtKeyUsages[oid]
    }

    /// Converts the DER bytes of a KeyUsage BIT STRING (leading byte is the
    /// count of unused bits, then the value bytes, most-significant bit first)
    /// into Go's little-endian `x509.KeyUsage` bitmask where digitalSignature
    /// is bit 0.
    static func goKeyUsageValue(fromBitString der: [UInt8]) -> Int {
        guard der.count >= 1 else { return 0 }
        let valueBytes = Array(der.dropFirst())
        var value = 0
        for (byteIndex, byte) in valueBytes.enumerated() {
            for bitInByte in 0..<8 where (byte >> (7 - bitInByte)) & 1 == 1 {
                value |= (1 << (byteIndex * 8 + bitInByte))
            }
        }
        return value
    }

    private static let goSignatureAlgorithms: [ASN1ObjectIdentifier: Int] = [
        [1, 2, 840, 113549, 1, 1, 2]: 1,  // md2WithRSA
        [1, 2, 840, 113549, 1, 1, 4]: 2,  // md5WithRSA
        [1, 2, 840, 113549, 1, 1, 5]: 3,  // sha1WithRSA
        [1, 2, 840, 113549, 1, 1, 11]: 4,  // sha256WithRSA
        [1, 2, 840, 113549, 1, 1, 12]: 5,  // sha384WithRSA
        [1, 2, 840, 113549, 1, 1, 13]: 6,  // sha512WithRSA
        [1, 2, 840, 10045, 4, 1]: 9,  // ecdsaWithSHA1
        [1, 2, 840, 10045, 4, 3, 2]: 10,  // ecdsaWithSHA256
        [1, 2, 840, 10045, 4, 3, 3]: 11,  // ecdsaWithSHA384
        [1, 2, 840, 10045, 4, 3, 4]: 12,  // ecdsaWithSHA512
        [1, 3, 101, 112]: 16,  // ed25519
    ]

    private static let goPublicKeyAlgorithms: [ASN1ObjectIdentifier: Int] = [
        [1, 2, 840, 113549, 1, 1, 1]: 1,  // RSA
        [1, 2, 840, 10040, 4, 1]: 2,       // DSA
        [1, 2, 840, 10045, 2, 1]: 3,       // ECDSA
        [1, 3, 101, 112]: 4,               // Ed25519
    ]

    private static let goExtKeyUsages: [ASN1ObjectIdentifier: Int] = [
        [2, 5, 29, 37, 0]: 0,              // any
        [1, 3, 6, 1, 5, 5, 7, 3, 1]: 1,    // serverAuth
        [1, 3, 6, 1, 5, 5, 7, 3, 2]: 2,    // clientAuth
        [1, 3, 6, 1, 5, 5, 7, 3, 3]: 3,    // codeSigning
        [1, 3, 6, 1, 5, 5, 7, 3, 4]: 4,    // emailProtection
        [1, 3, 6, 1, 5, 5, 7, 3, 5]: 5,    // ipsecEndSystem
        [1, 3, 6, 1, 5, 5, 7, 3, 6]: 6,    // ipsecTunnel
        [1, 3, 6, 1, 5, 5, 7, 3, 7]: 7,    // ipsecUser
        [1, 3, 6, 1, 5, 5, 7, 3, 8]: 8,  // timeStamping
        [1, 3, 6, 1, 5, 5, 7, 3, 9]: 9,  // ocspSigning
        [1, 3, 6, 1, 4, 1, 311, 10, 3, 3]: 10,  // microsoftServerGatedCrypto
        [2, 16, 840, 1, 113730, 4, 1]: 11,  // netscapeServerGatedCrypto
        [1, 3, 6, 1, 4, 1, 311, 2, 1, 22]: 12,  // microsoftCommercialCodeSigning
        [1, 3, 6, 1, 4, 1, 311, 61, 1, 1]: 13,  // microsoftKernelCodeSigning
    ]
}
