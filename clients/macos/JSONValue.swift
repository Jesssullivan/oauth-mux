import Foundation

/// Dynamic, sendable JSON for a versioned control API. No credential types are
/// available to this client; values represent redacted state and action handles.
enum JSONValue: Codable, Sendable, Equatable {
    case object([String: JSONValue]), array([JSONValue]), string(String)
    case integer(UInt64), number(Double), bool(Bool), null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(UInt64.self) { self = .integer(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else { self = .object(try container.decode([String: JSONValue].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    subscript(_ field: String) -> JSONValue {
        if case .object(let value) = self { return value[field] ?? .null }
        return .null
    }
    var string: String? { if case .string(let value) = self { return value }; return nil }
    var number: Double? {
        switch self { case .integer(let value): return Double(value); case .number(let value): return value; default: return nil }
    }
    var boolean: Bool? { if case .bool(let value) = self { return value }; return nil }
    var array: [JSONValue] { if case .array(let value) = self { return value }; return [] }
    var display: String {
        switch self {
        case .string(let value): return value
        case .integer(let value): return String(value)
        case .number(let value): return String(format: "%.12g", value)
        case .bool(let value): return value ? "Yes" : "No"
        default: return "Unknown"
        }
    }
    func at(_ path: String) -> JSONValue {
        path.split(separator: ".").reduce(self) { $0[String($1)] }
    }
}
