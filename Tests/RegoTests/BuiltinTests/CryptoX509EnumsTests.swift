import SwiftASN1
import Testing
import X509

@testable import Rego

extension BuiltinTests {
    @Suite("BuiltinTests - CryptoX509 Enums", .tags(.builtins))
    struct CryptoX509EnumsTests {}
}

extension BuiltinTests.CryptoX509EnumsTests {
    @Test func signatureAlgorithmMapsToGoInts() {
        #expect(BuiltinFuncs.goSignatureAlgorithm(.sha1WithRSAEncryption) == 3)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.sha256WithRSAEncryption) == 4)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.sha384WithRSAEncryption) == 5)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.sha512WithRSAEncryption) == 6)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.ecdsaWithSHA256) == 10)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.ecdsaWithSHA384) == 11)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.ecdsaWithSHA512) == 12)
        #expect(BuiltinFuncs.goSignatureAlgorithm(.ed25519) == 16)
    }

    @Test func publicKeyAlgorithmMapsToGoInts() {
        #expect(BuiltinFuncs.goPublicKeyAlgorithm([1, 2, 840, 113549, 1, 1, 1]) == 1)  // RSA
        #expect(BuiltinFuncs.goPublicKeyAlgorithm([1, 2, 840, 10045, 2, 1]) == 3)  // ECDSA
        #expect(BuiltinFuncs.goPublicKeyAlgorithm([1, 3, 101, 112]) == 4)  // Ed25519
        #expect(BuiltinFuncs.goPublicKeyAlgorithm([9, 9, 9]) == 0)  // unknown
    }

    @Test func extKeyUsageMapsToGoInts() {
        #expect(BuiltinFuncs.goExtKeyUsage([1, 3, 6, 1, 5, 5, 7, 3, 1]) == 1)  // serverAuth
        #expect(BuiltinFuncs.goExtKeyUsage([1, 3, 6, 1, 5, 5, 7, 3, 2]) == 2)  // clientAuth
        #expect(BuiltinFuncs.goExtKeyUsage([9, 9, 9]) == nil)
    }

    @Test func keyUsageBitStringToGoBitmask() {
        // digitalSignature only: unused-bits=7, value 0b1000_0000.
        #expect(BuiltinFuncs.goKeyUsageValue(fromBitString: [0x07, 0x80]) == 1)
        // digitalSignature + keyEncipherment: value 0b1010_0000, unused=5.
        #expect(BuiltinFuncs.goKeyUsageValue(fromBitString: [0x05, 0xa0]) == 5)
        // certSign + crlSign: bits 5 and 6 → 0b0000_0110 in Go terms (32|64=96).
        #expect(BuiltinFuncs.goKeyUsageValue(fromBitString: [0x01, 0x06]) == 96)
    }
}
