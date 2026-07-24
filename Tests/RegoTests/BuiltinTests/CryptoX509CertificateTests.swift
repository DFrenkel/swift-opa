import AST
import Foundation
import Testing
import X509

@testable import Rego

extension BuiltinTests {
    @Suite("BuiltinTests - CryptoX509 Certificate", .tags(.builtins))
    struct CryptoX509CertificateTests {}
}

extension BuiltinTests.CryptoX509CertificateTests {
    // Sub-structure Raw* blobs are deferred this round; compare every other
    // field against OPA's golden output.
    static let deferredKeys: Set<String> = [
        "RawTBSCertificate", "RawSubject", "RawIssuer", "RawSubjectPublicKeyInfo",
    ]

    private static func stripDeferred(_ value: AST.RegoValue) -> AST.RegoValue {
        guard case .object(let pairs) = value else { return value }
        var out: [AST.RegoValue: AST.RegoValue] = [:]
        for (k, v) in pairs {
            if case .string(let key) = k, deferredKeys.contains(key) { continue }
            out[k] = v
        }
        return .object(out)
    }

    @Test(arguments: ["ecdsa-leaf", "rsa-leaf", "ed25519-leaf", "chain"])
    func matchesOpaGolden(name: String) throws {
        let fixture = try BuiltinTests.cryptoX509Fixture(name)
        let got = try BuiltinFuncs.x509ParseCertificates(ctx: BuiltinContext(), args: [.string(fixture.input)])

        let gotCerts = try #require(got.asArray)
        let wantCerts = try #require(fixture.want.asArray)
        try #require(gotCerts.count == wantCerts.count)

        for (got, want) in zip(gotCerts, wantCerts) {
            #expect(got == Self.stripDeferred(want))
        }
    }
}
