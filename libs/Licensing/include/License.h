#pragma once

#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QString>

namespace licensing {

struct ResourceLimit {
    bool unlimited = false;
    int value = 0;
};

struct LicensedModule {
    QString id;
    QString displayName;
    ResourceLimit cameraLimit;
};

class LicenseValidator;

struct License {
    static constexpr int LegacySchemaVersion = 1;
    static constexpr int CurrentSchemaVersion = 2;

    int version = LegacySchemaVersion;
    QString licenseId;
    QString product;
    QString owner;
    QDateTime issueDate;
    QDateTime expiryDate;
    int fingerprintPolicyVersion = 1;
    QString fingerprintHash;
    QJsonArray fingerprintComponents;
    QString nonce;

    QJsonObject toJson() const;
    bool fromJson(const QJsonObject& object);
    QByteArray canonical() const;

    bool entitlementsAvailable() const;
    bool isModuleEnabled(const QString& moduleId) const;
    ResourceLimit moduleCameraLimit(const QString& moduleId) const;
    ResourceLimit userLimit() const;
    QList<LicensedModule> licensedModules() const;

private:
    QJsonValue m_entitlementsJson;
    bool m_entitlementsAvailable = false;
    QList<LicensedModule> m_licensedModules;
    ResourceLimit m_userLimit;

    bool activateEntitlements(QString* error = nullptr);

    friend class LicenseValidator;
};

} // namespace licensing
