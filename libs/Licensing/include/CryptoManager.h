#pragma once

#include <QByteArray>

namespace licensing {

class CryptoManager {
public:
    static QByteArray sha256(const QByteArray& data);
    static bool verifyRsaSha256(const QByteArray& payload,
                                const QByteArray& signature,
                                const QByteArray& publicKeyPem);
};

} // namespace licensing
