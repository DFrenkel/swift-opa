import AST
import Foundation
import Testing

@testable import Rego

extension BuiltinTests {
    @Suite("BuiltinTests - CryptoX509", .tags(.builtins))
    struct CryptoX509Tests {}
}

extension BuiltinTests.CryptoX509Tests {
    // A PKCS#1 RSA private key (from the upstream OPA compliance suite) and its
    // expected JWK representation.
    static let rsaPrivateKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA9D/bK4171aiTNUkrUCHKGMLSQooV+o3wdz2889h9iv0HhhBJ
        CAGU54K3duB8ofHpmYL50QodcR4RLw1vSkaI+FPdPDMyKxKj/YcmofJjz4kW+Iqw
        FbBcbMnKnEVzye+CyW9YYOTu0xWtcgen80zGp2opG0GZX86hBjjXJnjOdrJTk6x2
        NAiJIbjsQevysmj+2MyqVm8widxw0x+rGhTaCD+ZXWitN0a0WO1aaA8c/7i99I9z
        he2peKvXzEtMaqYO9ptHcYmq2z0QWvZuJVMv5Yn0mScLWyh91R099IOtn6sNaMMs
        OyTpi7E/2IlVgI2uKGPEopKkMFV8Fl2YaAbo7wIDAQABAoIBAAyMZ08ygqU0dvOq
        4a3JPp/NCo5el8h6mFsX8eg5PCHy4/sQRSBDLIpEXfaei+iqDA1V/E2wDlksaUeY
        khony4uui1Q3cSFjYMd6tRJm6JfV/DcisO88U1NHfsBOlSdPxdFhhhHcUSTJHVMZ
        b5iBXkdlnd0HnsCcVguCyhLw6/KPFyiA+NYRz68flxze7admyVp5C6i/HbMPq8Pr
        MilBUvOFtxuaGeJBAiavuzUe9I70dRwpe424tMvisSA8h7Xbm8BeN/PJHDV/2JrI
        URgQ563yQ5So/Qg8AgxXRkpgWM9zAh7r31PBO86vq/B4ZbON/TtWdcZVsAcVB4Pk
        tqc8JNkCgYEA+g8V+y92SETdcwUkbd5O9Fg5CkfdsALsBXVH6FunrCUV5HS9l5o6
        MMBbJ/08odW/bP5BmOa4A/Hbk9uG/UfQn2KQ3HCgPlxUEwQO07R1/FcQOe4xmyG6
        JpDgQ30viE1RtlCkceQWUeitCIqZsYu0i8sLZLWJH+V/07OB4G17ELMCgYEA+g1v
        hrlAFNhZvrIX/zcP3xF2pZ+AqkFXdL/tWQZkWAVToONn/LlXTH71C/TO2x+OaQRm
        qX1bA9Zhyjf1gYQN9RenjUswvggk0aY2Tk28wUqowMGSsjQHmZ20EphHNMWNJpdS
        fKFfrQIFKCnLlpQVNz+j3bLWZUnq+jPaYnJP7NUCgYEA48qcVo7c7Ga3aNEVZ3St
        bg90HrZq760pvqshDz13V+0MrWnfUFxxh/mi0KHy+uYRlMNllFkQ5p8LTP0dUlt6
        Y8dReU6r20MWX6BBtX9eP7o8ENm4nL4zqnAtq609gKgWuMNrmkiSQJl6Dx7bdY5z
        sSkNPvfUa5cQRBTxSjXRdtsCgYBHrzpdwRXh4/Q2ew/uFnbyWCtPZ96W8IyF58+/
        SdnSchR7dzYEeY3RXEQb3V6/6tgEu0JDLLC+9OKr+kbjjlwB+3oJQ5kBoYwMnj3L
        TPXj4+dk+xl3BPt4yoEpI4amVkwU2CTJnemzy3R3AyReUq2SXSg5El/sQbifaeYd
        eu/20QKBgH/5IZHGBKiRAe1ww2FzOpDtL8VXXTe3EAXKutfajrHTqPz9+lXknX/D
        UMosh264nYXYS29WqxhJVutbE9u8e0VpuY1qIN9/3R0WKfTLTMUFlZtbqTepvsy1
        W2UbK732I4Nfp0/mtUvOSdMZO8dxbSdEeMnw/Ec8QgxK9a1rRu9+
        -----END RSA PRIVATE KEY-----
        """

    static let rsaPrivateKeyJWK: AST.RegoValue = .object([
        .string("kty"): .string("RSA"),
        .string("n"): .string(
            "9D_bK4171aiTNUkrUCHKGMLSQooV-o3wdz2889h9iv0HhhBJCAGU54K3duB8ofHpmYL50QodcR4RLw1vSkaI-FPdPDMyKxKj_YcmofJjz4kW-IqwFbBcbMnKnEVzye-CyW9YYOTu0xWtcgen80zGp2opG0GZX86hBjjXJnjOdrJTk6x2NAiJIbjsQevysmj-2MyqVm8widxw0x-rGhTaCD-ZXWitN0a0WO1aaA8c_7i99I9zhe2peKvXzEtMaqYO9ptHcYmq2z0QWvZuJVMv5Yn0mScLWyh91R099IOtn6sNaMMsOyTpi7E_2IlVgI2uKGPEopKkMFV8Fl2YaAbo7w"
        ),
        .string("e"): .string("AQAB"),
        .string("d"): .string(
            "DIxnTzKCpTR286rhrck-n80Kjl6XyHqYWxfx6Dk8IfLj-xBFIEMsikRd9p6L6KoMDVX8TbAOWSxpR5iSGifLi66LVDdxIWNgx3q1Embol9X8NyKw7zxTU0d-wE6VJ0_F0WGGEdxRJMkdUxlvmIFeR2Wd3QeewJxWC4LKEvDr8o8XKID41hHPrx-XHN7tp2bJWnkLqL8dsw-rw-syKUFS84W3G5oZ4kECJq-7NR70jvR1HCl7jbi0y-KxIDyHtdubwF4388kcNX_YmshRGBDnrfJDlKj9CDwCDFdGSmBYz3MCHuvfU8E7zq-r8Hhls439O1Z1xlWwBxUHg-S2pzwk2Q"
        ),
        .string("p"): .string(
            "-g8V-y92SETdcwUkbd5O9Fg5CkfdsALsBXVH6FunrCUV5HS9l5o6MMBbJ_08odW_bP5BmOa4A_Hbk9uG_UfQn2KQ3HCgPlxUEwQO07R1_FcQOe4xmyG6JpDgQ30viE1RtlCkceQWUeitCIqZsYu0i8sLZLWJH-V_07OB4G17ELM"
        ),
        .string("q"): .string(
            "-g1vhrlAFNhZvrIX_zcP3xF2pZ-AqkFXdL_tWQZkWAVToONn_LlXTH71C_TO2x-OaQRmqX1bA9Zhyjf1gYQN9RenjUswvggk0aY2Tk28wUqowMGSsjQHmZ20EphHNMWNJpdSfKFfrQIFKCnLlpQVNz-j3bLWZUnq-jPaYnJP7NU"
        ),
        .string("dp"): .string(
            "48qcVo7c7Ga3aNEVZ3Stbg90HrZq760pvqshDz13V-0MrWnfUFxxh_mi0KHy-uYRlMNllFkQ5p8LTP0dUlt6Y8dReU6r20MWX6BBtX9eP7o8ENm4nL4zqnAtq609gKgWuMNrmkiSQJl6Dx7bdY5zsSkNPvfUa5cQRBTxSjXRdts"
        ),
        .string("dq"): .string(
            "R686XcEV4eP0NnsP7hZ28lgrT2felvCMhefPv0nZ0nIUe3c2BHmN0VxEG91ev-rYBLtCQyywvvTiq_pG445cAft6CUOZAaGMDJ49y0z14-PnZPsZdwT7eMqBKSOGplZMFNgkyZ3ps8t0dwMkXlKtkl0oORJf7EG4n2nmHXrv9tE"
        ),
        .string("qi"): .string(
            "f_khkcYEqJEB7XDDYXM6kO0vxVddN7cQBcq619qOsdOo_P36VeSdf8NQyiyHbridhdhLb1arGElW61sT27x7RWm5jWog33_dHRYp9MtMxQWVm1upN6m-zLVbZRsrvfYjg1-nT-a1S85J0xk7x3FtJ0R4yfD8RzxCDEr1rWtG734"
        ),
    ])

    static let happyPathTests: [BuiltinTests.TestCase] = [
        BuiltinTests.TestCase(
            description: "parses a PKCS#1 RSA private key into a JWK",
            name: "crypto.x509.parse_rsa_private_key",
            args: [.string(rsaPrivateKeyPEM)],
            expected: .success(rsaPrivateKeyJWK)
        ),
        BuiltinTests.TestCase(
            description: "parse_private_keys returns one key",
            name: "crypto.parse_private_keys",
            args: [.string(rsaPrivateKeyPEM)],
            expected: .success(.array([rsaPrivateKeyJWK]))
        ),
        BuiltinTests.TestCase(
            description: "parse_private_keys returns null for empty input",
            name: "crypto.parse_private_keys",
            args: [.string("")],
            expected: .success(.null)
        ),
        BuiltinTests.TestCase(
            description: "parse_private_keys returns empty array for non-PEM input",
            name: "crypto.parse_private_keys",
            args: [.string("nope")],
            expected: .success(.array([]))
        ),
    ]

    static var allTests: [BuiltinTests.TestCase] {
        [
            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_certificates", sampleArgs: ["certs"],
                argIndex: 0, argName: "certs",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),

            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_and_verify_certificates", sampleArgs: ["certs"],
                argIndex: 0, argName: "certs",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),

            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_and_verify_certificates_with_options",
                sampleArgs: ["certs", ["a": 1]],
                argIndex: 0, argName: "certs",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),
            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_and_verify_certificates_with_options",
                sampleArgs: ["certs", ["a": 1]],
                argIndex: 1, argName: "options",
                allowedArgTypes: ["object"],
                generateNumberOfArgsTest: false),

            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_certificate_request", sampleArgs: ["csr"],
                argIndex: 0, argName: "csr",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),

            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_keypair", sampleArgs: ["cert", "key"],
                argIndex: 0, argName: "cert",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),
            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_keypair", sampleArgs: ["cert", "key"],
                argIndex: 1, argName: "key",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: false),

            BuiltinTests.generateFailureTests(
                builtinName: "crypto.x509.parse_rsa_private_key", sampleArgs: ["pem"],
                argIndex: 0, argName: "pem",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),

            BuiltinTests.generateFailureTests(
                builtinName: "crypto.parse_private_keys", sampleArgs: ["keys"],
                argIndex: 0, argName: "keys",
                allowedArgTypes: ["string"],
                generateNumberOfArgsTest: true),

            happyPathTests,
        ].flatMap { $0 }
    }

    @Test(arguments: allTests)
    func testBuiltins(tc: BuiltinTests.TestCase) async throws {
        try await BuiltinTests.testBuiltin(tc: tc)
    }
}
