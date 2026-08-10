#include "PlatformIdentity.h"

#include "PlatformIdentityCore.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

namespace licensing {
namespace {

platform_core::Values toCore(const PlatformIdentityValues& values) {
    return {values.productUuid.toStdString(),
            values.productSerial.toStdString(),
            values.boardSerial.toStdString()};
}

PlatformIdentityValues fromCore(const platform_core::Values& values) {
    return {QString::fromStdString(values.productUuid),
            QString::fromStdString(values.productSerial),
            QString::fromStdString(values.boardSerial)};
}

void copyError(const std::string& source, QString* destination) {
    if (destination) {
        *destination = QString::fromStdString(source);
    }
}

bool isTrustedRootControlledPath(const QString& path) {
#ifdef Q_OS_UNIX
    const QFileInfo fileInfo(path);
    if (!fileInfo.exists() || !fileInfo.isFile() || fileInfo.ownerId() != 0) {
        return false;
    }
    const QFileDevice::Permissions unsafeWrite =
        QFileDevice::WriteGroup | QFileDevice::WriteOther;
    if (fileInfo.permissions() & unsafeWrite) {
        return false;
    }

    const QFileInfo directoryInfo(fileInfo.absolutePath());
    return directoryInfo.exists()
           && directoryInfo.isDir()
           && directoryInfo.ownerId() == 0
           && !(directoryInfo.permissions() & unsafeWrite);
#else
    Q_UNUSED(path)
    return false;
#endif
}

bool fail(QString* error, const QString& message) {
    if (error) {
        *error = message;
    }
    return false;
}

} // namespace

bool PlatformIdentityValues::hasProductUuid() const {
    return !productUuid.isEmpty();
}

bool PlatformIdentityValues::hasSerialPair() const {
    return !productSerial.isEmpty() && !boardSerial.isEmpty();
}

bool PlatformIdentityValues::hasTrustworthyIdentity() const {
    return hasProductUuid() || hasSerialPair();
}

bool PlatformIdentityValues::isEmpty() const {
    return productUuid.isEmpty() && productSerial.isEmpty() && boardSerial.isEmpty();
}

QString PlatformIdentity::snapshotFormat() {
    return QString::fromStdString(platform_core::snapshotFormat());
}

QString PlatformIdentity::defaultSnapshotPath() {
    return QString::fromStdString(platform_core::defaultSnapshotPath());
}

QString PlatformIdentity::normalizeProductUuid(const QString& value) {
    return QString::fromStdString(
        platform_core::normalizeProductUuid(value.toStdString()));
}

QString PlatformIdentity::normalizeSerial(const QString& value) {
    return QString::fromStdString(
        platform_core::normalizeSerial(value.toStdString()));
}

bool PlatformIdentity::isUsableProductUuid(const QString& value) {
    return !normalizeProductUuid(value).isEmpty();
}

bool PlatformIdentity::isUsableSerial(const QString& value) {
    return !normalizeSerial(value).isEmpty();
}

DirectPlatformIdentity PlatformIdentity::readDirect() {
    const platform_core::DirectIdentity result = platform_core::readDirect();
    return {fromCore(result.values), result.inaccessibleDmi};
}

QString PlatformIdentity::currentBootId() {
    return QString::fromStdString(platform_core::currentBootId());
}

QByteArray PlatformIdentity::createSnapshot(const PlatformIdentityValues& values,
                                            const QString& bootId,
                                            QString* error) {
    std::string coreError;
    const std::string snapshot = platform_core::createSnapshot(
        toCore(values), bootId.toStdString(), &coreError);
    copyError(coreError, error);
    return QByteArray::fromStdString(snapshot);
}

SnapshotStatus PlatformIdentity::parseSnapshot(
    const QByteArray& json,
    const QString& currentBootId,
    PlatformIdentityValues& values,
    QString* error) {
    values = {};
    const QString normalizedCurrentBootId = normalizeProductUuid(currentBootId);
    if (normalizedCurrentBootId.isEmpty()) {
        fail(error, QStringLiteral("The current Linux boot ID is unavailable."));
        return SnapshotStatus::Invalid;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        fail(error, QStringLiteral("The hardware identity snapshot is not valid JSON."));
        return SnapshotStatus::Invalid;
    }

    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("format")).toString() != snapshotFormat()
        || !root.value(QStringLiteral("version")).isDouble()
        || root.value(QStringLiteral("version")).toDouble() != SnapshotVersion
        || !root.value(QStringLiteral("boot_id")).isString()
        || !root.value(QStringLiteral("platform")).isObject()) {
        fail(error, QStringLiteral("The hardware identity snapshot format is invalid."));
        return SnapshotStatus::Invalid;
    }

    const QString snapshotBootId = normalizeProductUuid(
        root.value(QStringLiteral("boot_id")).toString());
    if (snapshotBootId.isEmpty()) {
        fail(error, QStringLiteral("The hardware identity snapshot boot ID is invalid."));
        return SnapshotStatus::Invalid;
    }

    const QJsonObject platform = root.value(QStringLiteral("platform")).toObject();
    auto readOptional = [&](const QString& name,
                            QString& output,
                            bool uuid) -> bool {
        if (!platform.contains(name)) {
            return true;
        }
        if (!platform.value(name).isString()) {
            return fail(error, QStringLiteral(
                "A hardware identity snapshot field has the wrong type."));
        }
        output = uuid
                     ? normalizeProductUuid(platform.value(name).toString())
                     : normalizeSerial(platform.value(name).toString());
        return !output.isEmpty()
               || fail(error, QStringLiteral(
                   "A hardware identity snapshot field is invalid."));
    };

    if (!readOptional(QStringLiteral("product_uuid"), values.productUuid, true)
        || !readOptional(QStringLiteral("product_serial"), values.productSerial,
                         false)
        || !readOptional(QStringLiteral("board_serial"), values.boardSerial,
                         false)) {
        values = {};
        return SnapshotStatus::Invalid;
    }

    if (snapshotBootId != normalizedCurrentBootId) {
        fail(error, QStringLiteral(
            "The hardware identity snapshot belongs to a previous Linux boot."));
        return SnapshotStatus::Stale;
    }
    return SnapshotStatus::Valid;
}

SnapshotStatus PlatformIdentity::readTrustedSnapshot(
    const QString& path,
    const QString& currentBootId,
    PlatformIdentityValues& values,
    QString* error) {
    values = {};
    if (!QFileInfo::exists(path)) {
        return SnapshotStatus::NotFound;
    }
    if (!isTrustedRootControlledPath(path)) {
        fail(error, QStringLiteral(
            "The hardware identity snapshot is not root-controlled."));
        return SnapshotStatus::Untrusted;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        fail(error, QStringLiteral("The hardware identity snapshot cannot be read."));
        return SnapshotStatus::Invalid;
    }
    return parseSnapshot(file.readAll(), currentBootId, values, error);
}

bool PlatformIdentity::writeSnapshotAtomically(
    const QString& path,
    const PlatformIdentityValues& values,
    const QString& bootId,
    QString* error) {
    std::string coreError;
    const bool written = platform_core::writeSnapshotAtomically(
        path.toStdString(), toCore(values), bootId.toStdString(), &coreError);
    copyError(coreError, error);
    return written;
}

} // namespace licensing
