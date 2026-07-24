import AST
import SwiftASN1
import X509

// Builds the Go `pkix.Name` object for a certificate's Subject or Issuer. OPA
// emits every pkix.Name field, so we reproduce the full shape: the named
// convenience fields (string arrays, or null when absent), the string
// CommonName/SerialNumber, and the ordered `Names` list of every attribute.
extension BuiltinFuncs {
    static func nameObject(_ dn: DistinguishedName) -> AST.RegoValue {
        var commonName = ""
        var serialNumber = ""
        var country: [String] = []
        var organization: [String] = []
        var organizationalUnit: [String] = []
        var locality: [String] = []
        var province: [String] = []
        var streetAddress: [String] = []
        var postalCode: [String] = []
        var names: [AST.RegoValue] = []

        for rdn in dn {
            for attribute in rdn {
                let oid = attribute.type.oidComponents
                let value = String(attribute.value) ?? ""
                names.append(
                    .object([
                        .string("Type"): .array(oid.map { .number(RegoNumber(int: Int64($0))) }),
                        .string("Value"): .string(value),
                    ]))

                if oid == [2, 5, 4, 3] {
                    commonName = value
                } else if oid == [2, 5, 4, 5] {
                    serialNumber = value
                } else if oid == [2, 5, 4, 6] {
                    country.append(value)
                } else if oid == [2, 5, 4, 7] {
                    locality.append(value)
                } else if oid == [2, 5, 4, 8] {
                    province.append(value)
                } else if oid == [2, 5, 4, 9] {
                    streetAddress.append(value)
                } else if oid == [2, 5, 4, 10] {
                    organization.append(value)
                } else if oid == [2, 5, 4, 11] {
                    organizationalUnit.append(value)
                } else if oid == [2, 5, 4, 17] {
                    postalCode.append(value)
                }
            }
        }

        return .object([
            .string("CommonName"): .string(commonName),
            .string("SerialNumber"): .string(serialNumber),
            .string("Country"): namesArrayOrNull(country),
            .string("Organization"): namesArrayOrNull(organization),
            .string("OrganizationalUnit"): namesArrayOrNull(organizationalUnit),
            .string("Locality"): namesArrayOrNull(locality),
            .string("Province"): namesArrayOrNull(province),
            .string("StreetAddress"): namesArrayOrNull(streetAddress),
            .string("PostalCode"): namesArrayOrNull(postalCode),
            .string("Names"): names.isEmpty ? .null : .array(names),
            .string("ExtraNames"): .null,
        ])
    }
}
