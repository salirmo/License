#pragma once

#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>

namespace licensing {

struct License {
    int version = 1;
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
};

} // namespace licensing
