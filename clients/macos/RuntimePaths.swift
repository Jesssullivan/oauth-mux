import Darwin
import Foundation

enum RuntimePathError: LocalizedError {
    case unsafePath, unavailableDirectory, unsafeOwner, unsafePermissions, socketTooLong
    var errorDescription: String? {
        switch self {
        case .unsafePath: return "The selected Omux path is unsafe."
        case .unavailableDirectory: return "The Omux directory is unavailable or unsafe."
        case .unsafeOwner: return "The Omux directory belongs to another user."
        case .unsafePermissions: return "The Omux directory must be private to the current user."
        case .socketTooLong: return "The Omux socket path is too long."
        }
    }
}

enum RuntimePaths {
    static var isDevelopment: Bool { ProcessInfo.processInfo.environment["OMUX_INSTANCE"] == "dev" }
    static var serviceLabel: String { isDevelopment ? "ai.xoxd.omux.dev" : "ai.xoxd.omux" }
    private static func absolute(_ path: String) throws {
        guard path.utf8.count >= 2, path.hasPrefix("/"), !path.hasSuffix("/"),
              !path.utf8.contains(0) else { throw RuntimePathError.unsafePath }
        for component in path.dropFirst().split(separator: "/", omittingEmptySubsequences: false) {
            guard !component.isEmpty, component != ".", component != ".." else {
                throw RuntimePathError.unsafePath
            }
        }
    }

    private static func openPrivateDirectory(_ path: String) throws -> Int32 {
        try absolute(path)
        var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw RuntimePathError.unavailableDirectory }
        var transferred = false
        defer { if !transferred { Darwin.close(descriptor) } }
        for component in path.dropFirst().split(separator: "/") {
            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0 else { throw RuntimePathError.unavailableDirectory }
            guard (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
                  metadata.st_uid == getuid() || metadata.st_uid == 0 else {
                throw RuntimePathError.unsafeOwner
            }
            guard metadata.st_mode & 0o022 == 0 ||
                    (metadata.st_uid == 0 && metadata.st_mode & mode_t(S_ISVTX) != 0) else {
                throw RuntimePathError.unsafePermissions
            }
            let next = String(component).withCString {
                Darwin.openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard next >= 0 else { throw RuntimePathError.unavailableDirectory }
            Darwin.close(descriptor)
            descriptor = next
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw RuntimePathError.unavailableDirectory }
        guard (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR), metadata.st_uid == getuid() else {
            throw RuntimePathError.unsafeOwner
        }
        guard metadata.st_mode & 0o777 == 0o700 else { throw RuntimePathError.unsafePermissions }
        transferred = true
        return descriptor
    }

    static func validateSocketPath(_ path: String) throws {
        try absolute(path)
        guard path.utf8.count <= 103 else { throw RuntimePathError.socketTooLong }
        guard let separator = path.lastIndex(of: "/") else { throw RuntimePathError.unsafePath }
        let descriptor = try openPrivateDirectory(String(path[..<separator]))
        defer { Darwin.close(descriptor) }
        let name = String(path[path.index(after: separator)...])
        var metadata = stat()
        let result = name.withCString { fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW) }
        if result != 0 {
            if errno == ENOENT { return }
            throw RuntimePathError.unavailableDirectory
        }
        guard (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFSOCK), metadata.st_uid == getuid() else {
            throw RuntimePathError.unsafeOwner
        }
        guard metadata.st_mode & 0o777 == 0o600 else { throw RuntimePathError.unsafePermissions }
    }

    static func defaultControlSocket() throws -> String {
        if let instance = ProcessInfo.processInfo.environment["OMUX_INSTANCE"],
           instance != "default", instance != "dev" { throw RuntimePathError.unsafePath }
        if let selected = ProcessInfo.processInfo.environment["OMUX_SOCKET"] {
            try validateSocketPath(selected)
            return selected
        }
        guard let home = ProcessInfo.processInfo.environment["HOME"] else {
            throw RuntimePathError.unsafePath
        }
        try absolute(home)
        let socket = home + "/Library/Application Support/" + (isDevelopment ? "Omux-dev" : "Omux") + "/run/control.sock"
        guard socket.utf8.count <= 103 else { throw RuntimePathError.socketTooLong }
        return socket
    }
}
