#include "LicenseManager.h"
#include "PubKey.h"

#include <QSettings>

namespace licensing {
namespace {

const QString kProductName = QStringLiteral("MyApp");
const QString kOrganizationName = QStringLiteral("SGI");
const QString kApplicationName = QStringLiteral("FaceDetectionViewer");
const QString kSettingsKey = QStringLiteral("license_key");

} // namespace

LicenseManager::LicenseManager()
    : m_validator(QByteArray(lic::kVendorPublicKey), kProductName) {
}

ValidationError LicenseManager::validate(const QString& licenseKey,
                                         License& outLicense) const {
    return m_validator.validateData(licenseKey.trimmed().toUtf8(), outLicense);
}

ValidationError LicenseManager::validateStoredLicense(License& outLicense) const {
    return validate(storedLicenseKey(), outLicense);
}

QString LicenseManager::storedLicenseKey() const {
    QSettings settings(kOrganizationName, kApplicationName);
    return settings.value(kSettingsKey).toString().trimmed();
}

void LicenseManager::storeLicenseKey(const QString& licenseKey) const {
    QSettings settings(kOrganizationName, kApplicationName);
    settings.setValue(kSettingsKey, licenseKey.trimmed());
    settings.sync();
}

void LicenseManager::clearStoredLicense() const {
    QSettings settings(kOrganizationName, kApplicationName);
    settings.remove(kSettingsKey);
    settings.sync();
}

QString LicenseManager::errorToString(ValidationError error) const {
    return m_validator.errorToString(error);
}

} // namespace licensing
