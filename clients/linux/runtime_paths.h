#pragma once

#include <QString>
#include <optional>

// Same selection contract as src/paths.zig. Errors contain classifications,
// never filesystem paths. Callers must surface failures instead of falling back.
namespace OmuxRuntimePaths {
QString defaultControlSocket();
QString controlSocketForState(const QString &state, const std::optional<QString> &runtime);
void validateSocketPath(const QString &path);
}
