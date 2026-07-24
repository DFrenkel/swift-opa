import AST
import Testing
import X509

@testable import Rego

extension BuiltinTests {
    @Suite("BuiltinTests - CryptoX509 Name", .tags(.builtins))
    struct CryptoX509NameTests {}
}

extension BuiltinTests.CryptoX509NameTests {
    // Subject and Issuer of every parsed cert must match OPA's pkix.Name object.
    @Test(arguments: ["ecdsa-leaf", "rsa-leaf", "chain"])
    func subjectAndIssuerMatchGolden(name: String) throws {
        let fixture = try BuiltinTests.cryptoX509Fixture(name)
        let wantCerts = try #require(fixture.want.asArray)
        try #require(fixture.certificates.count == wantCerts.count)

        for (cert, want) in zip(fixture.certificates, wantCerts) {
            let wantObj = try #require(want.asObject)
            #expect(BuiltinFuncs.nameObject(cert.subject) == wantObj[.string("Subject")])
            #expect(BuiltinFuncs.nameObject(cert.issuer) == wantObj[.string("Issuer")])
        }
    }

    @Test func absentFieldsAreNullAndSerialNumberEmpty() {
        // A DN with only a CommonName: every other convenience field is null and
        // SerialNumber is the empty string, matching Go.
        let dn = try! DistinguishedName {
            CommonName("only.example.com")
        }
        let obj = try! #require(BuiltinFuncs.nameObject(dn).asObject)
        #expect(obj[.string("CommonName")] == .string("only.example.com"))
        #expect(obj[.string("SerialNumber")] == .string(""))
        #expect(obj[.string("Organization")] == .null)
        #expect(obj[.string("Country")] == .null)
        #expect(obj[.string("ExtraNames")] == .null)
    }
}
