#include "PlatformIdentityCore.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <system_error>
#include <vector>

#ifdef __unix__
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace licensing::platform_core {
namespace {

const std::set<std::string>& invalidIdentifierValues() {
    static const std::set<std::string> values = {
        "0",
        "na",
        "n/a",
        "none",
        "null",
        "unknown",
        "undefined",
        "invalid",
        "not set",
        "not present",
        "not provided",
        "not specified",
        "not available",
        "not applicable",
        "default",
        "default string",
        "system serial number",
        "serial number",
        "system product name",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "123456789"
    };
    return values;
}

std::string simplifiedLower(const std::string& value) {
    std::string normalized;
    normalized.reserve(value.size());
    bool pendingSpace = false;
    for (const unsigned char character : value) {
        if (std::isspace(character)) {
            pendingSpace = !normalized.empty();
            continue;
        }
        if (pendingSpace) {
            normalized.push_back(' ');
            pendingSpace = false;
        }
        normalized.push_back(
            static_cast<char>(std::tolower(character)));
    }
    return normalized;
}

std::string compactUuid(const std::string& value) {
    std::string compact;
    for (const char character : simplifiedLower(value)) {
        if (character != '-' && character != '{' && character != '}'
            && character != ' ') {
            compact.push_back(character);
        }
    }
    return compact;
}

bool isAsciiHex(const std::string& value) {
    return std::all_of(value.cbegin(), value.cend(), [](unsigned char value) {
        return (value >= '0' && value <= '9')
               || (value >= 'a' && value <= 'f');
    });
}

bool isRepeatedPlaceholder(const std::string& value) {
    std::string compact;
    for (const unsigned char character : value) {
        if ((character >= 'a' && character <= 'z')
            || (character >= '0' && character <= '9')) {
            compact.push_back(static_cast<char>(character));
        }
    }
    if (compact.empty()) {
        return true;
    }
    return (compact.front() == '0' || compact.front() == 'f')
           && std::all_of(compact.cbegin(), compact.cend(),
                          [first = compact.front()](char character) {
                              return character == first;
                          });
}

std::string readTextFile(const std::string& path, bool* inaccessible) {
    std::ifstream input(path, std::ios::binary);
    if (input) {
        std::ostringstream contents;
        contents << input.rdbuf();
        return contents.str();
    }

#ifdef __unix__
    struct stat status {};
    if (inaccessible && ::stat(path.c_str(), &status) == 0) {
        *inaccessible = true;
    }
#else
    (void) inaccessible;
#endif
    return {};
}

std::string escapeJson(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    static constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char character : value) {
        switch (character) {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (character < 0x20U) {
                escaped += "\\u00";
                escaped.push_back(hex[(character >> 4U) & 0x0fU]);
                escaped.push_back(hex[character & 0x0fU]);
            } else {
                escaped.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    return escaped;
}

bool fail(std::string* error, const std::string& message) {
    if (error) {
        *error = message;
    }
    return false;
}

void appendJsonField(std::string& object,
                     const std::string& name,
                     const std::string& value) {
    if (!object.empty()) {
        object.push_back(',');
    }
    object += "\"" + name + "\":\"" + escapeJson(value) + "\"";
}

#ifdef __unix__
bool writeAll(int fileDescriptor, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t written = ::write(
            fileDescriptor, data.data() + offset, data.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}
#endif

} // namespace

bool Values::hasProductUuid() const {
    return !productUuid.empty();
}

bool Values::hasSerialPair() const {
    return !productSerial.empty() && !boardSerial.empty();
}

bool Values::hasTrustworthyIdentity() const {
    return hasProductUuid() || hasSerialPair();
}

std::string snapshotFormat() {
    return "sgi-platform-identity-1";
}

std::string defaultSnapshotPath() {
    return "/var/lib/sgi-license/platform-identity.json";
}

std::string normalizeProductUuid(const std::string& value) {
    const std::string compact = compactUuid(value);
    if (compact.size() != 32 || !isAsciiHex(compact)
        || isRepeatedPlaceholder(compact)) {
        return {};
    }
    return compact.substr(0, 8) + '-'
           + compact.substr(8, 4) + '-'
           + compact.substr(12, 4) + '-'
           + compact.substr(16, 4) + '-'
           + compact.substr(20, 12);
}

std::string normalizeSerial(const std::string& value) {
    const std::string normalized = simplifiedLower(value);
    if (invalidIdentifierValues().count(normalized) != 0
        || isRepeatedPlaceholder(normalized)
        || normalized.size() < 3) {
        return {};
    }
    const bool hasUsefulCharacter = std::any_of(
        normalized.cbegin(), normalized.cend(), [](unsigned char character) {
            return (character >= 'a' && character <= 'z')
                   || (character >= '0' && character <= '9');
        });
    return hasUsefulCharacter ? normalized : std::string{};
}

DirectIdentity readDirect() {
    DirectIdentity result;
    bool inaccessible = false;
    result.values.productUuid = normalizeProductUuid(readTextFile(
        "/sys/class/dmi/id/product_uuid", &inaccessible));
    result.values.productSerial = normalizeSerial(readTextFile(
        "/sys/class/dmi/id/product_serial", &inaccessible));
    result.values.boardSerial = normalizeSerial(readTextFile(
        "/sys/class/dmi/id/board_serial", &inaccessible));
    result.inaccessibleDmi = inaccessible;
    return result;
}

std::string currentBootId() {
    return normalizeProductUuid(readTextFile(
        "/proc/sys/kernel/random/boot_id", nullptr));
}

std::string createSnapshot(const Values& values,
                           const std::string& bootId,
                           std::string* error) {
    if (error) {
        error->clear();
    }
    const std::string normalizedBootId = normalizeProductUuid(bootId);
    if (normalizedBootId.empty()) {
        fail(error, "The current Linux boot ID is invalid.");
        return {};
    }

    Values normalized;
    if (!values.productUuid.empty()) {
        normalized.productUuid = normalizeProductUuid(values.productUuid);
        if (normalized.productUuid.empty()) {
            fail(error, "The product UUID is invalid.");
            return {};
        }
    }
    if (!values.productSerial.empty()) {
        normalized.productSerial = normalizeSerial(values.productSerial);
        if (normalized.productSerial.empty()) {
            fail(error, "The product serial is invalid.");
            return {};
        }
    }
    if (!values.boardSerial.empty()) {
        normalized.boardSerial = normalizeSerial(values.boardSerial);
        if (normalized.boardSerial.empty()) {
            fail(error, "The board serial is invalid.");
            return {};
        }
    }

    std::string platform;
    if (!normalized.productUuid.empty()) {
        appendJsonField(platform, "product_uuid", normalized.productUuid);
    }
    if (!normalized.productSerial.empty()) {
        appendJsonField(platform, "product_serial", normalized.productSerial);
    }
    if (!normalized.boardSerial.empty()) {
        appendJsonField(platform, "board_serial", normalized.boardSerial);
    }

    return "{\"format\":\"" + snapshotFormat()
           + "\",\"version\":" + std::to_string(SnapshotVersion)
           + ",\"boot_id\":\"" + normalizedBootId
           + "\",\"platform\":{" + platform + "}}";
}

bool writeSnapshotAtomically(const std::string& path,
                             const Values& values,
                             const std::string& bootId,
                             std::string* error) {
    const std::string json = createSnapshot(values, bootId, error);
    if (json.empty()) {
        return false;
    }

#ifdef __unix__
    const std::filesystem::path target(path);
    const std::filesystem::path parent = target.parent_path();
    if (parent.empty()) {
        return fail(error,
                    "The hardware identity snapshot directory cannot be created.");
    }
    std::error_code filesystemError;
    std::filesystem::create_directories(parent, filesystemError);
    if (filesystemError) {
        return fail(error,
                    "The hardware identity snapshot directory cannot be created.");
    }

    struct stat directoryStatus {};
    if (::lstat(parent.c_str(), &directoryStatus) != 0
        || !S_ISDIR(directoryStatus.st_mode)
        || directoryStatus.st_uid != 0) {
        return fail(error,
                    "The hardware identity snapshot directory is not root-controlled.");
    }
    if (::chmod(parent.c_str(), 0755) != 0) {
        return fail(error,
                    "The hardware identity snapshot directory permissions cannot be set.");
    }

    std::string temporaryTemplate = path + ".tmp.XXXXXX";
    std::vector<char> temporaryBuffer(temporaryTemplate.cbegin(),
                                      temporaryTemplate.cend());
    temporaryBuffer.push_back('\0');
    const int descriptor = ::mkstemp(temporaryBuffer.data());
    if (descriptor < 0) {
        return fail(error,
                    "The hardware identity snapshot cannot be opened for writing.");
    }
    const std::string temporaryPath(temporaryBuffer.data());
    (void) ::fcntl(descriptor, F_SETFD, FD_CLOEXEC);

    const std::string contents = json + '\n';
    const bool committed = writeAll(descriptor, contents)
                           && ::fchmod(descriptor, 0644) == 0
                           && ::fsync(descriptor) == 0;
    const int closeResult = ::close(descriptor);
    if (!committed || closeResult != 0
        || ::rename(temporaryPath.c_str(), path.c_str()) != 0) {
        ::unlink(temporaryPath.c_str());
        return fail(error,
                    "The hardware identity snapshot cannot be committed atomically.");
    }

#ifdef O_DIRECTORY
    const int directoryDescriptor = ::open(
        parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directoryDescriptor >= 0) {
        (void) ::fsync(directoryDescriptor);
        (void) ::close(directoryDescriptor);
    }
#endif
    return true;
#else
    (void) path;
    return fail(error,
                "Atomic hardware identity snapshots are supported only on Unix.");
#endif
}

} // namespace licensing::platform_core
