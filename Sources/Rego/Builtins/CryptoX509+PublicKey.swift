import AST
import Foundation
import SwiftASN1
import X509

extension BuiltinFuncs {
    /// Parses a SubjectPublicKeyInfo DER blob into Go's `PublicKeyAlgorithm`
    /// integer and the matching `PublicKey` object. `Certificate.PublicKey` is
    /// opaque about key components, so both parse paths build the key object
    /// from the SPKI DER here.
    ///
    /// Shapes match Go's `json.Marshal`:
    /// - RSA: `{"N": <decimal string>, "E": <int>}`
    /// - ECDSA: `{"Curve": {}, "X": <decimal string>, "Y": <decimal string>}`
    /// - Ed25519: base64 string of the raw key
    ///
    /// Big-integer members are emitted as decimal strings for now (see
    /// `decimalString`). Returns nil for unsupported key types so the caller can
    /// zero-value the field.
    static func publicKeyObject(fromSPKIDer der: [UInt8]) -> (algorithm: Int, key: AST.RegoValue)? {
        guard let root = try? DER.parse(der),
            case .constructed(let top) = root.content
        else { return nil }
        let topNodes = Array(top)
        guard topNodes.count >= 2,
            case .constructed(let algSeq) = topNodes[0].content,
            let oidNode = Array(algSeq).first,
            let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode),
            case .primitive(let bitBytes) = topNodes[1].content
        else { return nil }

        let algorithm = goPublicKeyAlgorithm(oid)
        // BIT STRING content leads with the unused-bits count byte.
        let keyBits = Array(bitBytes.dropFirst())

        switch algorithm {
        case 1:  // RSA: BIT STRING wraps SEQUENCE { modulus INTEGER, exponent INTEGER }
            guard let rsaRoot = try? DER.parse(keyBits),
                case .constructed(let rsaSeq) = rsaRoot.content
            else { return nil }
            var iterator = rsaSeq.makeIterator()
            guard let nNode = iterator.next(), let eNode = iterator.next(),
                let nBytes = try? Array(ArraySlice<UInt8>(derEncoded: nNode)),
                let eBytes = try? Array(ArraySlice<UInt8>(derEncoded: eNode))
            else { return nil }
            let e = eBytes.reduce(0) { $0 * 256 + Int($1) }
            return (
                algorithm,
                .object([
                    .string("N"): .string(decimalString(fromBigEndianBytes: nBytes)),
                    .string("E"): .number(RegoNumber(int: Int64(e))),
                ])
            )
        case 3:  // ECDSA: BIT STRING is 0x04 || X || Y (uncompressed point)
            guard keyBits.first == 0x04 else { return nil }
            let coord = Array(keyBits.dropFirst())
            guard coord.count % 2 == 0 else { return nil }
            let half = coord.count / 2
            return (
                algorithm,
                .object([
                    .string("Curve"): .object([:]),
                    .string("X"): .string(decimalString(fromBigEndianBytes: Array(coord[0..<half]))),
                    .string("Y"): .string(decimalString(fromBigEndianBytes: Array(coord[half...]))),
                ])
            )
        case 4:  // Ed25519: BIT STRING is the raw key bytes
            return (algorithm, .string(Data(keyBits).base64EncodedString()))
        default:
            return nil
        }
    }

    // Converts a big-endian magnitude to its base-10 string using schoolbook
    // long-form arithmetic. Used for SerialNumber and RSA/ECDSA key components,
    // which exceed Int64 and Decimal precision. When RegoNumber gains
    // arbitrary precision these callers emit real numbers instead of strings.
    static func decimalString(fromBigEndianBytes bytes: [UInt8]) -> String {
        var digits: [UInt8] = [0]  // little-endian base-10 digits
        for byte in bytes {
            var carry = Int(byte)
            for i in 0..<digits.count {
                let value = Int(digits[i]) * 256 + carry
                digits[i] = UInt8(value % 10)
                carry = value / 10
            }
            while carry > 0 {
                digits.append(UInt8(carry % 10))
                carry /= 10
            }
        }
        return String(digits.reversed().map { Character(String($0)) })
    }
}
