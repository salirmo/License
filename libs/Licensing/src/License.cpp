#include "License.h"

#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

#include <algorithm>
#include <cmath>
#include <limits>

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

bool fail(QString* error, const QString& message) {
    if (error) {
        *error = message;
    }
    return false;
}

QString normalizeModuleId(const QString& moduleId) {
    return moduleId.trimmed().toLower();
}

bool isValidModuleId(const QString& moduleId) {
    const QString normalized = normalizeModuleId(moduleId);
    static const QRegularExpression pattern(
        QStringLiteral("^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"));
    return normalized.size() <= 64 && pattern.match(normalized).hasMatch();
}

bool positiveInteger(const QJsonValue& value, int& output) {
    if (!value.isDouble()) {
        return false;
    }

    const double number = value.toDouble();
    if (!std::isfinite(number)
        || std::floor(number) != number
        || number < 1.0
        || number > static_cast<double>(std::numeric_limits<int>::max())) {
        return false;
    }
    output = static_cast<int>(number);
    return true;
}

bool parseResourceLimit(const QJsonValue& value,
                        ResourceLimit& output,
                        QString* error) {
    if (!value.isObject()) {
        return fail(error, QStringLiteral("A resource limit must be an object."));
    }

    const QJsonObject object = value.toObject();
    if (!object.value(QStringLiteral("mode")).isString()) {
        return fail(error, QStringLiteral("A resource limit mode is missing."));
    }

    const QString mode = object.value(QStringLiteral("mode")).toString();
    ResourceLimit parsed;
    if (mode == QStringLiteral("limited")) {
        if (!positiveInteger(object.value(QStringLiteral("value")),
                             parsed.value)) {
            return fail(error, QStringLiteral(
                "A limited resource must contain a positive integer value."));
        }
    } else if (mode == QStringLiteral("unlimited")) {
        if (object.contains(QStringLiteral("value"))) {
            return fail(error, QStringLiteral(
                "An unlimited resource must not contain a value."));
        }
        parsed.unlimited = true;
    } else {
        return fail(error, QStringLiteral("A resource limit mode is invalid."));
    }

    output = parsed;
    return true;
}

} // namespace

QJsonObject License::toJson() const {
    QJsonObject fingerprint;
    fingerprint.insert(QStringLiteral("hash"), fingerprintHash);
    fingerprint.insert(QStringLiteral("components"), fingerprintComponents);
    // Policy 1 predates this field. Omitting it for legacy licenses preserves
    // their exact canonical bytes and therefore their existing signatures.
    if (fingerprintPolicyVersion > 1) {
        fingerprint.insert(QStringLiteral("policy_version"),
                           fingerprintPolicyVersion);
    }

    QJsonObject object;
    object.insert(QStringLiteral("version"), version);
    object.insert(QStringLiteral("license_id"), licenseId);
    object.insert(QStringLiteral("product"), product);
    object.insert(QStringLiteral("owner"), owner);
    object.insert(QStringLiteral("issue_date"),
                  issueDate.toUTC().toString(Qt::ISODate));
    object.insert(QStringLiteral("expiry_date"),
                  expiryDate.isValid()
                      ? expiryDate.toUTC().toString(Qt::ISODate)
                      : QString());
    object.insert(QStringLiteral("fingerprint"), fingerprint);
    if (version >= CurrentSchemaVersion && !m_entitlementsJson.isUndefined()) {
        object.insert(QStringLiteral("entitlements"), m_entitlementsJson);
    }
    object.insert(QStringLiteral("nonce"), nonce);
    return object;
}

bool License::fromJson(const QJsonObject& object) {
    m_entitlementsJson = {};
    m_entitlementsAvailable = false;
    m_licensedModules.clear();
    m_userLimit = {};

    if (!object.value(QStringLiteral("version")).isDouble()
        || !object.value(QStringLiteral("license_id")).isString()
        || !object.value(QStringLiteral("product")).isString()
        || !object.value(QStringLiteral("issue_date")).isString()
        || !object.value(QStringLiteral("fingerprint")).isObject()) {
        return false;
    }

    const double versionValue =
        object.value(QStringLiteral("version")).toDouble();
    if (versionValue == LegacySchemaVersion) {
        version = LegacySchemaVersion;
    } else if (versionValue == CurrentSchemaVersion) {
        version = CurrentSchemaVersion;
    } else {
        return false;
    }
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

    fingerprintPolicyVersion = 1;
    if (fingerprint.contains(QStringLiteral("policy_version"))) {
        if (!fingerprint.value(QStringLiteral("policy_version")).isDouble()) {
            return false;
        }
        const double policyValue =
            fingerprint.value(QStringLiteral("policy_version")).toDouble();
        fingerprintPolicyVersion = static_cast<int>(policyValue);
        if (fingerprintPolicyVersion < 1
            || policyValue != static_cast<double>(fingerprintPolicyVersion)) {
            return false;
        }
    }

    fingerprintHash = fingerprint.value(QStringLiteral("hash")).toString().trimmed();
    fingerprintComponents = fingerprint.value(QStringLiteral("components")).toArray();

    if (version == CurrentSchemaVersion) {
        if (!object.contains(QStringLiteral("entitlements"))) {
            return false;
        }
        // Preserve the exact signed value for canonicalization. Detailed
        // entitlement parsing intentionally happens only after every existing
        // license validation step succeeds.
        m_entitlementsJson = object.value(QStringLiteral("entitlements"));
    }

    return !licenseId.isEmpty()
           && !product.isEmpty()
           && issueDate.isValid()
           && (expiryText.isEmpty() || expiryDate.isValid())
           && !fingerprintHash.isEmpty()
           && !fingerprintComponents.isEmpty();
}

QByteArray License::canonical() const {
    return QJsonDocument(sortedObject(toJson())).toJson(QJsonDocument::Compact);
}

bool License::activateEntitlements(QString* error) {
    m_entitlementsAvailable = false;
    m_licensedModules.clear();
    m_userLimit = {};

    if (version == LegacySchemaVersion) {
        return true;
    }
    if (version != CurrentSchemaVersion || !m_entitlementsJson.isObject()) {
        return fail(error, QStringLiteral("Entitlements must be an object."));
    }

    const QJsonObject entitlements = m_entitlementsJson.toObject();
    if (!entitlements.value(QStringLiteral("modules")).isArray()) {
        return fail(error, QStringLiteral("The entitlement module list is missing."));
    }

    ResourceLimit parsedUserLimit;
    if (!parseResourceLimit(entitlements.value(QStringLiteral("user_limit")),
                            parsedUserLimit, error)) {
        return false;
    }

    QList<LicensedModule> parsedModules;
    QSet<QString> moduleIds;
    const QJsonArray modules =
        entitlements.value(QStringLiteral("modules")).toArray();
    for (const QJsonValue& value : modules) {
        if (!value.isObject()) {
            return fail(error, QStringLiteral("A licensed module must be an object."));
        }

        const QJsonObject object = value.toObject();
        if (!object.value(QStringLiteral("id")).isString()) {
            return fail(error, QStringLiteral("A licensed module ID is missing."));
        }
        if (object.contains(QStringLiteral("display_name"))
            && !object.value(QStringLiteral("display_name")).isString()) {
            return fail(error, QStringLiteral(
                "A licensed module display name must be a string."));
        }

        LicensedModule module;
        module.id = normalizeModuleId(
            object.value(QStringLiteral("id")).toString());
        if (!isValidModuleId(module.id)) {
            return fail(error, QStringLiteral("A licensed module ID is invalid."));
        }
        if (module.id == QStringLiteral("other")) {
            return fail(error, QStringLiteral(
                "Module ID 'other' is reserved and cannot be licensed."));
        }
        if (moduleIds.contains(module.id)) {
            return fail(error, QStringLiteral("A licensed module ID is duplicated."));
        }
        module.displayName = object.value(
            QStringLiteral("display_name")).toString().trimmed();
        if (!parseResourceLimit(object.value(QStringLiteral("camera_limit")),
                                module.cameraLimit, error)) {
            return false;
        }
        moduleIds.insert(module.id);
        parsedModules.append(module);
    }

    m_licensedModules = parsedModules;
    m_userLimit = parsedUserLimit;
    m_entitlementsAvailable = true;
    return true;
}

bool License::entitlementsAvailable() const {
    return m_entitlementsAvailable;
}

bool License::isModuleEnabled(const QString& moduleId) const {
    if (!m_entitlementsAvailable) {
        return false;
    }

    const QString normalizedId = normalizeModuleId(moduleId);
    if (!isValidModuleId(normalizedId)) {
        return false;
    }
    return std::any_of(
        m_licensedModules.cbegin(), m_licensedModules.cend(),
        [&normalizedId](const LicensedModule& module) {
            return module.id == normalizedId;
        });
}

ResourceLimit License::moduleCameraLimit(const QString& moduleId) const {
    if (!m_entitlementsAvailable) {
        return {};
    }

    const QString normalizedId = normalizeModuleId(moduleId);
    const auto module = std::find_if(
        m_licensedModules.cbegin(), m_licensedModules.cend(),
        [&normalizedId](const LicensedModule& candidate) {
            return candidate.id == normalizedId;
        });
    return module == m_licensedModules.cend()
               ? ResourceLimit{}
               : module->cameraLimit;
}

ResourceLimit License::userLimit() const {
    return m_entitlementsAvailable ? m_userLimit : ResourceLimit{};
}

QList<LicensedModule> License::licensedModules() const {
    return m_entitlementsAvailable ? m_licensedModules
                                   : QList<LicensedModule>{};
}

} // namespace licensing
