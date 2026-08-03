#include "LicenseValidator.h"

#include "CryptoManager.h"
#include "HardwareFingerprint.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>

#include <utility>

namespace licensing {

LicenseValidator::LicenseValidator(QByteArray publicKeyPem, QString expectedProduct)
    : m_publicKeyPem(std::move(publicKeyPem)),
      m_expectedProduct(std::move(expectedProduct)) {
}

QString LicenseValidator::errorToString(ValidationError error) const {
    switch (error) {
    case ValidationError::None:
        return QStringLiteral("OK");
    case ValidationError::JsonParseFailed:
        return QStringLiteral("Invalid license key format.");
    case ValidationError::FormatUnsupported:
        return QStringLiteral("Unsupported license format.");
    case ValidationError::SignatureInvalid:
        return QStringLiteral("The license signature is invalid.");
    case ValidationError::ProductMismatch:
        return QStringLiteral("This license belongs to a different product.");
    case ValidationError::FingerprintMismatch:
        return QStringLiteral("This license is not valid for this machine.");
    case ValidationError::Expired:
        return QStringLiteral("The license has expired.");
    case ValidationError::NotYetValid:
        return QStringLiteral("The license issue date is in the future.");
    case ValidationError::MalformedPayload:
        return QStringLiteral("The license payload is malformed.");
    }
    return QStringLiteral("Unknown license error.");
}

ValidationError LicenseValidator::validateData(const QByteArray& data,
                                               License& outLicense) const {
    if (data.trimmed().isEmpty() || m_publicKeyPem.trimmed().isEmpty()) {
        return ValidationError::JsonParseFailed;
    }

    const QByteArray jsonData = QByteArray::fromBase64(data.trimmed());
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return ValidationError::JsonParseFailed;
    }

    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("format")).toString()
        != QStringLiteral("acme-license-1")) {
        return ValidationError::FormatUnsupported;
    }
    if (!root.value(QStringLiteral("payload")).isObject()
        || !root.value(QStringLiteral("signature")).isString()) {
        return ValidationError::MalformedPayload;
    }

    License license;
    if (!license.fromJson(root.value(QStringLiteral("payload")).toObject())) {
        return ValidationError::MalformedPayload;
    }
    if (!m_expectedProduct.isEmpty() && license.product != m_expectedProduct) {
        return ValidationError::ProductMismatch;
    }

    const QByteArray signature = QByteArray::fromBase64(
        root.value(QStringLiteral("signature")).toString().toLatin1());
    if (signature.isEmpty()
        || !CryptoManager::verifyRsaSha256(
            license.canonical(), signature, m_publicKeyPem)) {
        return ValidationError::SignatureInvalid;
    }

    const QDateTime nowUtc = QDateTime::currentDateTimeUtc();
    if (license.issueDate > nowUtc.addSecs(60)) {
        return ValidationError::NotYetValid;
    }
    if (license.expiryDate.isValid() && nowUtc >= license.expiryDate) {
        return ValidationError::Expired;
    }

    HardwareFingerprint currentFingerprint;
    if (currentFingerprint.fingerprintHash() != license.fingerprintHash) {
        QList<HardwareFingerprint::Component> referenceComponents;
        for (const QJsonValue& value : license.fingerprintComponents) {
            if (!value.isObject()) {
                return ValidationError::MalformedPayload;
            }
            const QJsonObject object = value.toObject();
            const QString name = object.value(QStringLiteral("name")).toString().trimmed();
            const QString componentValue = object.value(QStringLiteral("value")).toString().trimmed();
            if (name.isEmpty() || componentValue.isEmpty()) {
                return ValidationError::MalformedPayload;
            }
            referenceComponents.append({
                name,
                componentValue,
                object.value(QStringLiteral("stable")).toBool()
            });
        }

        constexpr int hardwareChangeTolerance = 1;
        if (!currentFingerprint.tolerantMatch(referenceComponents,
                                              hardwareChangeTolerance)) {
            return ValidationError::FingerprintMismatch;
        }
    }

    outLicense = license;
    return ValidationError::None;
}

} // namespace licensing
