import Foundation

/// Runs the production parser over redacted wire fixtures. No daemon, vault,
/// service, provider or native application work is performed.
@main
struct SetupReadinessReportFixture {
    enum Failure: Error { case acceptedInvalid(String), rejectedValid(String), wrongProjection }
    static let phases = ["artifact", "service", "vault", "source", "identity", "grant", "native"]

    static func wire(_ allReady: Bool) -> [String: JSONValue] {
        ["schema_version": .integer(1), "ready": .bool(allReady), "seamless_handoff_proven": .bool(false),
         "findings": .array(phases.map { phase in
             let ready = allReady || phase != "native"
             return .object(["phase": .string(phase), "reason": .string(ready ? "ready" : "native_evidence_missing"),
                             "action": .string(ready ? "none" : "verify_native_capability")])
         })]
    }

    static func parseWire(_ fields: [String: JSONValue]) throws -> SetupReadinessReport {
        // Exercise the actual JSON decoding boundary, including boolean types.
        let bytes = try JSONEncoder().encode(JSONValue.object(fields))
        return try SetupReadinessReport.parse(JSONDecoder().decode(JSONValue.self, from: bytes))
    }

    static func rejects(_ fields: [String: JSONValue], _ name: String) throws {
        do { _ = try parseWire(fields) }
        catch SetupReadinessReport.InvalidReport.unsupported { return }
        throw Failure.acceptedInvalid(name)
    }

    static func main() throws {
        let pending = try parseWire(wire(false))
        let ready = try parseWire(wire(true))
        guard !pending.ready, ready.ready, pending.findings.count == 7,
              pending.findings.last?["action"].string == "verify_native_capability" else { throw Failure.wrongProjection }
        // Order is not authority: preserve a valid daemon order for display.
        var reordered = wire(false)
        reordered["findings"] = .array(Array(reordered["findings"]!.array.reversed()))
        guard try parseWire(reordered).findings.first?["phase"].string == "native" else { throw Failure.wrongProjection }
        var absent = wire(false); var absentFindings = absent["findings"]!.array
        absentFindings[6] = .object(["phase": .string("native"), "reason": .string("missing"), "action": .string("install_native_adapter")])
        absent["findings"] = .array(absentFindings)
        let missing = try parseWire(absent)
        guard !missing.ready, missing.findings.last?["action"].string == "install_native_adapter",
              pending.findings.last?["reason"].string == "native_evidence_missing" else { throw Failure.wrongProjection }

        for allReady in [false, true] {
            var contradictory = wire(allReady)
            contradictory["ready"] = .bool(!allReady)
            try rejects(contradictory, "aggregate contradicts phases")
        }
        for key in ["ready", "seamless_handoff_proven", "schema_version", "findings"] {
            var missing = wire(false); missing.removeValue(forKey: key)
            try rejects(missing, "missing " + key)
        }
        for bad in [JSONValue.string("false"), .integer(0), .null, .bool(true)] {
            var promoted = wire(false); promoted["seamless_handoff_proven"] = bad
            try rejects(promoted, "invalid seamless proof")
        }
        for bad in [JSONValue.string("false"), .integer(0), .null] {
            var malformed = wire(false); malformed["ready"] = bad
            try rejects(malformed, "nonboolean aggregate")
        }
        for count in [6, 8] {
            var malformed = wire(false); var findings = malformed["findings"]!.array
            if count == 6 { findings.removeLast() } else { findings.append(findings[0]) }
            malformed["findings"] = .array(findings)
            try rejects(malformed, "wrong phase count")
        }
        for key in ["phase", "reason", "action"] {
            for bad in [JSONValue.null, .integer(0), .string("")] {
                var malformed = wire(false); var findings = malformed["findings"]!.array
                guard case .object(var finding) = findings[0] else { throw Failure.wrongProjection }
                finding[key] = bad; findings[0] = .object(finding); malformed["findings"] = .array(findings)
                try rejects(malformed, "invalid finding " + key)
            }
        }
        for phase in ["service", "unsupported_phase"] {
            var malformed = wire(false); var findings = malformed["findings"]!.array
            guard case .object(var finding) = findings[0] else { throw Failure.wrongProjection }
            finding["phase"] = .string(phase); findings[0] = .object(finding); malformed["findings"] = .array(findings)
            try rejects(malformed, "duplicate or unknown phase")
        }
        var unknown = wire(false); var findings = unknown["findings"]!.array
        guard case .object(var native) = findings[6] else { throw Failure.wrongProjection }
        native["reason"] = .string("future_nonready_reason"); native["action"] = .string("future_action")
        findings[6] = .object(native); unknown["findings"] = .array(findings)
        let future = try parseWire(unknown)
        guard !future.ready else { throw Failure.rejectedValid("unknown nonready finding") }
        print("OMUX_SETUP_READINESS_FIXTURE_OK")
    }
}
