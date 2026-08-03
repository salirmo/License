#include "License.h"

#include <QJsonDocument>
#include <QStringList>
#include <QTimeZone>

#include <algorithm>

namespace licensing {
namespace {

QJsonObject sortedObject(const QJsonObject& input) {
    QStringList keys = input.keys();
    std::sort(keys.begin(), keys.end());

    QJsonObject output;
    for (const QString& key : keys) {
        output.insert(key, input.value(key));
    }
    return output;
}

} // namespace

QJsonObject License::toJson() const {
    QJsonObject fingerprint;
    fingerprint.insert(QStringLiteral("hash"), fingerprintHash);
    fingerprint.insert(QStringLiteral("components"), fingerprintComponents);

    QJsonObject object;
    object.insert(QStringLiteral("version"), version);
    object.insert(QStringLiteral("license_id"), licenseId);
    object.insert(QStringLiteral("product"), product);
    object.insert(QStringLiteral("owner"), owner);
    object.insert(QStringLiteral("issue_date"), issueDate.toUTC().toString(Qt::ISODate));
    object.insert(QStringLiteral("expiry_date"),
                  expiryDate.isValid() ? expiryDate.toUTC().toString(Qt::ISODate) : QString());
    object.insert(QStringLiteral("fingerprint"), fingerprint);
    object.insert(QStringLiteral("nonce"), nonce);
    return object;
}

bool License::fromJson(const QJsonObject& object) {
    if (!object.value(QStringLiteral("version")).isDouble()
        || !object.value(QStringLiteral("license_id")).isString()
        || !object.value(QStringLiteral("product")).isString()
        || !object.value(QStringLiteral("issue_date")).isString()
        || !object.value(QStringLiteral("fingerprint")).isObject()) {
        return false;
    }

    version = object.value(QStringLiteral("version")).toInt();
    licenseId = object.value(QStringLiteral("license_id")).toString().trimmed();
    product = object.value(QStringLiteral("product")).toString().trimmed();
    owner = object.value(QStringLiteral("owner")).toString();
    nonce = object.value(QStringLiteral("nonce")).toString();

    issueDate = QDateTime::fromString(
        object.value(QStringLiteral("issue_date")).toString(), Qt::ISODate);
    if (issueDate.isValid()) {
        issueDate = issueDate.toUTC();
    }

    expiryDate = {};
    const QString expiryText = object.value(QStringLiteral("expiry_date")).toString();
    if (!expiryText.isEmpty()) {
        expiryDate = QDateTime::fromString(expiryText, Qt::ISODate);
        if (expiryDate.isValid()) {
            expiryDate = expiryDate.toUTC();
        }
    }

    const QJsonObject fingerprint = object.value(QStringLiteral("fingerprint")).toObject();
    if (!fingerprint.value(QStringLiteral("hash")).isString()
        || !fingerprint.value(QStringLiteral("components")).isArray()) {
        return false;
    }
    fingerprintHash = fingerprint.value(QStringLiteral("hash")).toString().trimmed();
    fingerprintComponents = fingerprint.value(QStringLiteral("components")).toArray();

    return version == 1
           && !licenseId.isEmpty()
           && !product.isEmpty()
           && issueDate.isValid()
           && (expiryText.isEmpty() || expiryDate.isValid())
           && !fingerprintHash.isEmpty()
           && !fingerprintComponents.isEmpty();
}

QByteArray License::canonical() const {
    return QJsonDocument(sortedObject(toJson())).toJson(QJsonDocument::Compact);
}

} // namespace licensing
