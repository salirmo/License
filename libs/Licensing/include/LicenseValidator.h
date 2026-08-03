#pragma once

#include "License.h"

#include <QByteArray>
#include <QString>

namespace licensing {

enum class ValidationError {
    None,
    JsonParseFailed,
    FormatUnsupported,
    SignatureInvalid,
    ProductMismatch,
    FingerprintMismatch,
    Expired,
    NotYetValid,
    MalformedPayload
};

class LicenseValidator {
public:
    LicenseValidator(QByteArray publicKeyPem, QString expectedProduct);

    ValidationError validateData(const QByteArray& data, License& outLicense) const;
    QString errorToString(ValidationError error) const;

private:
    QByteArray m_publicKeyPem;
    QString m_expectedProduct;
};

} // namespace licensing
