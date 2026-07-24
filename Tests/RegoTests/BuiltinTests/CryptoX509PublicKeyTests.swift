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

    @Test func rsaPublicKeyObjectShape() throws {
        // SPKI DER for a tiny RSA key: modulus 0x010001 (65537), exponent 0x03.
        let rsaSPKI: [UInt8] = [
            0x30, 0x1c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x0b, 0x00, 0x30, 0x08, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x01, 0x03,
        ]
        let result = try #require(BuiltinFuncs.publicKeyObject(fromSPKIDer: rsaSPKI))
        #expect(result.algorithm == 1)
        #expect(
            result.key == .object([
                .string("N"): .string("65537"),
                .string("E"): .number(RegoNumber(int: 3)),
            ]))
    }

    @Test(arguments: ["ecdsa-leaf", "rsa-leaf", "ed25519-leaf"])
    func publicKeyMatchesGolden(name: String) throws {
        let fixture = try BuiltinTests.cryptoX509Fixture(name)
        let cert = try #require(fixture.certificates.first)
        var serializer = DER.Serializer()
        try serializer.serialize(cert.publicKey)
        let result = try #require(BuiltinFuncs.publicKeyObject(fromSPKIDer: serializer.serializedBytes))

        let wantCert = try #require(fixture.want.asArray?.first?.asObject)
        #expect(wantCert[.string("PublicKeyAlgorithm")] == .number(RegoNumber(int: Int64(result.algorithm))))
        #expect(result.key == wantCert[.string("PublicKey")])
    }
}
