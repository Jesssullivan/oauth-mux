import Darwin
import Foundation

enum ControlError: LocalizedError {
    case unavailable, peerMismatch, invalidFrame, incompatibleVersion, timedOut
    case unknownOutcome
    case declined(String)
    case mutationDeclined(String)
    var errorDescription: String? {
        switch self {
        case .unavailable: return "The Omux service is unavailable. Start the user service or reconnect."
        case .peerMismatch: return "The local service belongs to another user; connection refused."
        case .invalidFrame: return "The service returned an invalid or oversized control response."
        case .incompatibleVersion: return "The service uses an unsupported control protocol."
        case .timedOut: return "The service request timed out. Refresh state before repeating an action."
        case .unknownOutcome: return "Connection failed after requesting the action; its outcome may be unknown. Refresh before repeating it."
        case .declined(let message), .mutationDeclined(let message): return message
        }
    }
}

/// Blocking socket work is confined to a serial utility queue, away from the UI
/// and Swift's cooperative task executor. All mutable state is queue-owned. A
/// mutation is never automatically replayed after an uncertain transport result.
final class DaemonConnection: @unchecked Sendable {
    static let maximumFrame = 1024 * 1024
    let socketPath: String
    private let selectionError: Error?
    private var nextID: UInt64 = 1
    private let queue = DispatchQueue(label: "ai.xoxd.omux.control-transport", qos: .utility)

    init(socketPath: String? = nil) {
        if let socketPath {
            self.socketPath = socketPath
            self.selectionError = nil
        } else {
            do {
                self.socketPath = try RuntimePaths.defaultControlSocket()
                self.selectionError = nil
            } catch {
                self.socketPath = ""
                self.selectionError = error
            }
        }
    }

    func request(_ method: String, params: [String: JSONValue] = [:]) async throws -> JSONValue {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do { continuation.resume(returning: try self.requestSync(method, params: params)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func requestSync(_ method: String, params: [String: JSONValue]) throws -> JSONValue {
        let descriptor = try openSocket()
        defer { Darwin.close(descriptor) }
        let nativeOperation = method.hasPrefix("integrations.") && method != "integrations.status"
        let deadline = DispatchTime.now().uptimeNanoseconds + (nativeOperation ? 20_000_000_000 : 10_000_000_000)
        var remainder = Data()
        let handshake = try exchange(descriptor, method: "system.handshake",
            params: ["protocol_version": .number(2), "client": .string("omux-macos")],
            remainder: &remainder, deadline: deadline)
        guard handshake["protocol_version"].number == 2 else {
            throw ControlError.incompatibleVersion
        }
        do {
            return try exchange(descriptor, method: method, params: params,
                                remainder: &remainder, deadline: deadline)
        } catch ControlError.declined(let reason) {
            throw isRead(method, params: params) ? ControlError.declined(reason) : ControlError.mutationDeclined(reason)
        } catch ControlError.unavailable {
            throw isRead(method, params: params) ? ControlError.unavailable : ControlError.unknownOutcome
        } catch ControlError.timedOut {
            throw isRead(method, params: params) ? ControlError.timedOut : ControlError.unknownOutcome
        } catch ControlError.invalidFrame {
            throw isRead(method, params: params) ? ControlError.invalidFrame : ControlError.unknownOutcome
        }
    }

    private func isRead(_ method: String, params: [String: JSONValue]) -> Bool {
        if method == "setup.refresh" { return params.isEmpty }
        return ["state.snapshot", "events.watch", "accounts.list", "sources.list", "usage.summary",
         "integrations.status", "integrations.discover", "policy.get", "operation.status", "system.health", "reliability.export", "sources.catalog", "setup.readiness"].contains(method)
    }

    private func openSocket() throws -> Int32 {
        if let selectionError { throw selectionError }
        try RuntimePaths.validateSocketPath(socketPath)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(socketPath.utf8) + [UInt8(0)]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw ControlError.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: bytes)
        }
        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ControlError.unavailable }
        do {
            guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
                throw ControlError.unavailable
            }
            var enabled: Int32 = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                             socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                throw ControlError.unavailable
            }
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result < 0 {
                guard errno == EINPROGRESS else { throw ControlError.unavailable }
                try wait(descriptor, event: Int16(POLLOUT),
                         deadline: DispatchTime.now().uptimeNanoseconds + 3_000_000_000)
                var code: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &code, &length) == 0,
                      code == 0 else { throw ControlError.unavailable }
            }
            var uid: uid_t = 0
            var gid: gid_t = 0
            guard getpeereid(descriptor, &uid, &gid) == 0, uid == geteuid() else {
                throw ControlError.peerMismatch
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func wait(_ descriptor: Int32, event: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw ControlError.timedOut }
            let milliseconds = Int32(min(10_000, (deadline - now + 999_999) / 1_000_000))
            var pollDescriptor = pollfd(fd: descriptor, events: event, revents: 0)
            let result = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if result < 0 && errno == EINTR { continue }
            guard result > 0 else {
                throw result == 0 ? ControlError.timedOut : ControlError.unavailable
            }
            guard pollDescriptor.revents & event != 0 else { throw ControlError.unavailable }
            return
        }
    }

    private func exchange(_ descriptor: Int32, method: String,
                          params: [String: JSONValue], remainder: inout Data,
                          deadline: UInt64) throws -> JSONValue {
        let id = "mac-\(nextID)"
        nextID += 1
        var encoded = try JSONEncoder().encode(JSONValue.object([
            "jsonrpc": .string("2.0"), "id": .string(id),
            "method": .string(method), "params": .object(params)
        ]))
        encoded.append(0x0a)
        guard encoded.count <= Self.maximumFrame else { throw ControlError.invalidFrame }
        var offset = 0
        while offset < encoded.count {
            try wait(descriptor, event: Int16(POLLOUT), deadline: deadline)
            let written = encoded.withUnsafeBytes { buffer in
                Darwin.send(descriptor, buffer.baseAddress!.advanced(by: offset), encoded.count - offset, 0)
            }
            if written < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard written > 0 else { throw ControlError.unavailable }
            offset += written
        }
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            if let newline = remainder.firstIndex(of: 0x0a) {
                guard remainder.distance(from: remainder.startIndex, to: newline) <= Self.maximumFrame else {
                    throw ControlError.invalidFrame
                }
                let frame = remainder.prefix(upTo: newline)
                remainder.removeSubrange(...newline)
                let response: JSONValue
                do { response = try JSONDecoder().decode(JSONValue.self, from: Data(frame)) }
                catch { throw ControlError.invalidFrame }
                guard response["jsonrpc"].string == "2.0" else { throw ControlError.invalidFrame }
                // Notifications can arrive between handshake and request replies.
                if response["id"] == .null { continue }
                guard response["id"].string == id else { throw ControlError.invalidFrame }
                if response["error"] != .null {
                    throw ControlError.declined(response["error"]["message"].string
                                                ?? "The service declined the action.")
                }
                guard case .object = response["result"] else { throw ControlError.invalidFrame }
                return response["result"]
            }
            guard remainder.count <= Self.maximumFrame else { throw ControlError.invalidFrame }
            try wait(descriptor, event: Int16(POLLIN), deadline: deadline)
            let count = chunk.withUnsafeMutableBytes { buffer in
                Darwin.recv(descriptor, buffer.baseAddress, buffer.count, 0)
            }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { throw ControlError.unavailable }
            remainder.append(contentsOf: chunk.prefix(count))
        }
    }
}
