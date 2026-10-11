import Foundation

/// Validates the daemon's existing seven-phase setup contract before display.
/// Operational readiness is distinct from application or seamless-handoff proof.
struct SetupReadinessReport {
    enum InvalidReport: Error { case unsupported }
    let findings: [JSONValue]
    let ready: Bool

    static func parse(_ value: JSONValue) throws -> SetupReadinessReport {
        let expected: Set<String> = ["artifact", "service", "vault", "source", "identity", "grant", "native"]
        guard case .object = value,
              value["schema_version"].number == 1,
              case .array(let findings) = value["findings"], findings.count == expected.count,
              Set(findings.compactMap { $0["phase"].string }) == expected,
              findings.allSatisfy({ finding in
                  guard let reason = finding["reason"].string, let action = finding["action"].string else { return false }
                  return !reason.isEmpty && !action.isEmpty
              }),
              let ready = value["ready"].boolean,
              ready == findings.allSatisfy({ $0["reason"].string == "ready" }),
              value["seamless_handoff_proven"].boolean == false else {
            throw InvalidReport.unsupported
        }
        return SetupReadinessReport(findings: findings, ready: ready)
    }
}
