#pragma once

#include "HardwareFingerprint.h"
#include "License.h"

#include <QByteArray>
#include <QString>

#include <functional>

namespace licensing {

enum class ValidationError {
    None,
    JsonParseFailed,
    FormatUnsupported,
    LicenseVersionUnsupported,
    SignatureInvalid,
    ProductMismatch,
    FingerprintPolicyUnsupported,
    FingerprintInsufficient,
    FingerprintInvalid,
    FingerprintMismatch,
    Expired,
    NotYetValid,
    EntitlementsInvalid,
    MalformedPayload
};

class LicenseValidator {
public:
    using FingerprintProvider = std::function<HardwareFingerprint(int)>;

    LicenseValidator(QByteArray publicKeyPem,
                     QString expectedProduct,
                     FingerprintProvider fingerprintProvider = {});

    ValidationError validateData(const QByteArray& data, License& outLicense) const;
    QString errorToString(ValidationError error) const;

private:
    QByteArray m_publicKeyPem;
    QString m_expectedProduct;
    FingerprintProvider m_fingerprintProvider;
};

} // namespace licensing
