import Foundation
import SwiftASN1
import X509

extension BuiltinFuncs {
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
