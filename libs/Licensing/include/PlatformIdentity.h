#pragma once

#include <QByteArray>
#include <QString>

namespace licensing {

struct PlatformIdentityValues {
    QString productUuid;
    QString productSerial;
    QString boardSerial;

    bool hasProductUuid() const;
    bool hasSerialPair() const;
    bool hasTrustworthyIdentity() const;
    bool isEmpty() const;
};

enum class SnapshotStatus {
    Valid,
    NotFound,
    Stale,
    Invalid,
    Untrusted
};

struct DirectPlatformIdentity {
    PlatformIdentityValues values;
    bool inaccessibleDmi = false;
};

class PlatformIdentity {
public:
    static constexpr int SnapshotVersion = 1;

    static QString snapshotFormat();
    static QString defaultSnapshotPath();

    static QString normalizeProductUuid(const QString& value);
    static QString normalizeSerial(const QString& value);
    static bool isUsableProductUuid(const QString& value);
    static bool isUsableSerial(const QString& value);

    static DirectPlatformIdentity readDirect();
    static QString currentBootId();

    static QByteArray createSnapshot(const PlatformIdentityValues& values,
                                     const QString& bootId,
                                     QString* error = nullptr);
    static SnapshotStatus parseSnapshot(const QByteArray& json,
                                        const QString& currentBootId,
                                        PlatformIdentityValues& values,
                                        QString* error = nullptr);
    static SnapshotStatus readTrustedSnapshot(const QString& path,
                                              const QString& currentBootId,
                                              PlatformIdentityValues& values,
                                              QString* error = nullptr);
    static bool writeSnapshotAtomically(const QString& path,
                                        const PlatformIdentityValues& values,
                                        const QString& bootId,
                                        QString* error = nullptr);
};

} // namespace licensing
