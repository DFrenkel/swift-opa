import AST
import Foundation
import Testing
import X509

@testable import Rego

extension BuiltinTests {
    @Suite("BuiltinTests - CryptoX509 Extensions", .tags(.builtins))
    struct CryptoX509ExtensionsTests {}
}

extension BuiltinTests.CryptoX509ExtensionsTests {
    private func exts(_ fixture: String) throws -> [BuiltinFuncs.X509Ext] {
        let f = try BuiltinTests.cryptoX509Fixture(fixture)
        let cert = try #require(f.certificates.first)
        return BuiltinFuncs.normalizedExtensions(cert.extensions)
    }

    @Test func keyUsageAndExtKeyUsage() throws {
        let e = try exts("ecdsa-leaf")
        #expect(BuiltinFuncs.keyUsageValue(e) == 1)  // digitalSignature
        let eku = BuiltinFuncs.extKeyUsageValues(e)
        #expect(eku.known == [1, 2])  // serverAuth, clientAuth
        #expect(eku.unknown.isEmpty)
    }

    @Test func basicConstraintsAndKeyIds() throws {
        let e = try exts("ecdsa-leaf")
        let bc = BuiltinFuncs.basicConstraints(e)
        #expect(bc.valid == true)
        #expect(bc.isCA == false)
        #expect(bc.maxPathLen == -1)
        #expect(bc.maxPathLenZero == false)
        #expect(Data(BuiltinFuncs.subjectKeyID(e)).base64EncodedString() == "iJxtimAuTfwb+aUtBn5UYKreKvM=")
        #expect(Data(BuiltinFuncs.authorityKeyID(e)).base64EncodedString() == "St0GFhu89mi1dvWBtrtiGrpagS8=")
    }

    @Test func accessCrlAndPolicies() throws {
        let e = try exts("ecdsa-leaf")
        let access = BuiltinFuncs.accessInfo(e)
        #expect(access.ocsp == ["http://clients1.google.com/ocsp"])
        #expect(access.caIssuers == ["http://pki.google.com/GIAG2.crt"])
        #expect(BuiltinFuncs.crlDistributionPoints(e) == ["http://pki.google.com/GIAG2.crl"])
        #expect(BuiltinFuncs.policyIdentifiers(e) == [[1, 3, 6, 1, 4, 1, 11129, 2, 5, 1]])
    }

    @Test func subjectAltNames() throws {
        let e = try exts("ecdsa-leaf")
        let san = BuiltinFuncs.subjectAltNames(e)
        #expect(san.dns == ["mail.google.com"])
        #expect(san.email.isEmpty)
        #expect(san.ip.isEmpty)
        #expect(san.uris.isEmpty)
    }

    @Test func extensionListMatchesGolden() throws {
        let f = try BuiltinTests.cryptoX509Fixture("ecdsa-leaf")
        let cert = try #require(f.certificates.first)
        let list = BuiltinFuncs.extensionList(BuiltinFuncs.normalizedExtensions(cert.extensions))
        let want = try #require(f.want.asArray?.first?.asObject?[.string("Extensions")])
        #expect(list == want)
    }
}
