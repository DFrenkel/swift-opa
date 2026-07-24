import AST
import SwiftASN1
import Testing
import X509

@testable import Rego

extension BuiltinTests {
    @Suite("BuiltinTests - CryptoX509 PublicKey", .tags(.builtins))
    struct CryptoX509PublicKeyTests {}
}

extension BuiltinTests.CryptoX509PublicKeyTests {
    @Test func decimalStringHandlesSmallValues() {
        #expect(BuiltinFuncs.decimalString(fromBigEndianBytes: []) == "0")
        #expect(BuiltinFuncs.decimalString(fromBigEndianBytes: [0x00]) == "0")
        #expect(BuiltinFuncs.decimalString(fromBigEndianBytes: [0x01, 0x00]) == "256")
        #expect(BuiltinFuncs.decimalString(fromBigEndianBytes: [0xff]) == "255")
        #expect(BuiltinFuncs.decimalString(fromBigEndianBytes: [0x01, 0x00, 0x01]) == "65537")
    }

    @Test func decimalStringHandlesBigValues() {
        // 2^64 = 18446744073709551616 — beyond Int64 and Decimal precision.
        let twoTo64: [UInt8] = [0x01] + Array(repeating: 0x00, count: 8)
        #expect(BuiltinFuncs.decimalString(fromBigEndianBytes: twoTo64) == "18446744073709551616")
    }
}
