#pragma once

#include <string>

namespace licensing::platform_core {

struct Values {
    std::string productUuid;
    std::string productSerial;
    std::string boardSerial;

    bool hasProductUuid() const;
    bool hasSerialPair() const;
    bool hasTrustworthyIdentity() const;
};

struct DirectIdentity {
    Values values;
    bool inaccessibleDmi = false;
};

constexpr int SnapshotVersion = 1;

std::string snapshotFormat();
std::string defaultSnapshotPath();
std::string normalizeProductUuid(const std::string& value);
std::string normalizeSerial(const std::string& value);
DirectIdentity readDirect();
std::string currentBootId();
std::string createSnapshot(const Values& values,
                           const std::string& bootId,
                           std::string* error = nullptr);
bool writeSnapshotAtomically(const std::string& path,
                             const Values& values,
                             const std::string& bootId,
                             std::string* error = nullptr);

} // namespace licensing::platform_core
