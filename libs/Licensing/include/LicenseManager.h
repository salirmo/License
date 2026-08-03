#pragma once

#include "LicenseValidator.h"

namespace licensing {

class LicenseManager {
public:
    LicenseManager();

    ValidationError validate(const QString& licenseKey, License& outLicense) const;
    ValidationError validateStoredLicense(License& outLicense) const;
    QString storedLicenseKey() const;
    void storeLicenseKey(const QString& licenseKey) const;
    void clearStoredLicense() const;
    QString errorToString(ValidationError error) const;

private:
    LicenseValidator m_validator;
};

} // namespace licensing
