#include "LicenseValidator.h"

#include "CryptoManager.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>

#include <utility>

namespace licensing {

LicenseValidator::LicenseValidator(
    QByteArray publicKeyPem,
    QString expectedProduct,
    FingerprintProvider fingerprintProvider)
    : m_publicKeyPem(std::move(publicKeyPem)),
      m_expectedProduct(std::move(expectedProduct)),
      m_fingerprintProvider(std::move(fingerprintProvider)) {
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
    case ValidationError::FingerprintPolicyUnsupported:
        return QStringLiteral("The hardware fingerprint policy is not supported.");
    case ValidationError::FingerprintInsufficient:
        return QStringLiteral(
            "Not enough reliable hardware identifiers are available for secure activation.");
    case ValidationError::FingerprintInvalid:
        return QStringLiteral("The signed hardware fingerprint is inconsistent or invalid.");
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

    const int policyVersion = license.fingerprintPolicyVersion;
    if (!HardwareFingerprint::isSupportedPolicy(policyVersion)) {
        return ValidationError::FingerprintPolicyUnsupported;
    }

    QList<HardwareFingerprint::Component> referenceComponents;
    QString componentError;
    if (!HardwareFingerprint::parseComponents(license.fingerprintComponents,
                                              policyVersion,
                                              referenceComponents,
                                              &componentError)) {
        return ValidationError::MalformedPayload;
    }

    if (policyVersion == HardwareFingerprint::HardenedPolicyVersion) {
        if (!HardwareFingerprint::hasSufficientIdentifiers(referenceComponents,
                                                           policyVersion)) {
            return ValidationError::FingerprintInsufficient;
        }

        const QString referenceHash = HardwareFingerprint::calculateHash(
            referenceComponents, policyVersion);
        if (referenceHash.isEmpty()
            || referenceHash.compare(license.fingerprintHash,
                                     Qt::CaseInsensitive) != 0) {
            return ValidationError::FingerprintInvalid;
        }
    }

    const HardwareFingerprint currentFingerprint = m_fingerprintProvider
                                                       ? m_fingerprintProvider(policyVersion)
                                                       : HardwareFingerprint(policyVersion);
    if (policyVersion == HardwareFingerprint::HardenedPolicyVersion
        && !currentFingerprint.isSufficient()) {
        return ValidationError::FingerprintInsufficient;
    }

    if (currentFingerprint.fingerprintHash().compare(
            license.fingerprintHash, Qt::CaseInsensitive) != 0) {
        const HardwareFingerprint::MatchResult match =
            currentFingerprint.match(
                referenceComponents,
                HardwareFingerprint::HardwareChangeTolerance);
        if (!match.valid) {
            return ValidationError::FingerprintMismatch;
        }
    }

    outLicense = license;
    return ValidationError::None;
}

} // namespace licensing
