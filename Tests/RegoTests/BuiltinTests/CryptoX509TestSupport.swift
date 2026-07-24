import AST
import Foundation
import SwiftASN1
import X509

@testable import Rego

// Shared support for the CryptoX509 unit tests: loads golden fixtures captured
// from the opa binary and adapts them to this round's string-encoded big ints.
extension BuiltinTests {
    struct CryptoX509Fixture {
        let input: String
        let want: AST.RegoValue
        let certificates: [Certificate]
    }

    private struct FixtureFile: Decodable {
        let input: String
        let want: AST.RegoValue
    }

    static func cryptoX509Fixture(_ name: String) throws -> CryptoX509Fixture {
        let dir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/cryptox509")
        let data = try Data(contentsOf: dir.appendingPathComponent("\(name).json"))
        let file = try JSONDecoder().decode(FixtureFile.self, from: data)
        // Certificates only for the certs swift-certificates accepts; callers
        // that need the permissive path decode separately.
        let certs = (try? BuiltinFuncs.parseCertificates(from: file.input)) ?? []
        return CryptoX509Fixture(input: file.input, want: file.want, certificates: certs)
    }
}

extension AST.RegoValue {
    var asArray: [AST.RegoValue]? {
        if case .array(let a) = self { return a }
        return nil
    }
    var asObject: [AST.RegoValue: AST.RegoValue]? {
        if case .object(let o) = self { return o }
        return nil
    }
}
