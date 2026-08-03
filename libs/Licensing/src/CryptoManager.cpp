#include "CryptoManager.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace licensing {

QByteArray CryptoManager::sha256(const QByteArray& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.constData()),
           static_cast<size_t>(data.size()), digest);
    return QByteArray(reinterpret_cast<const char*>(digest), SHA256_DIGEST_LENGTH);
}

bool CryptoManager::verifyRsaSha256(const QByteArray& payload,
                                    const QByteArray& signature,
                                    const QByteArray& publicKeyPem) {
    BIO* bio = BIO_new_mem_buf(publicKeyPem.constData(), publicKeyPem.size());
    if (!bio) {
        return false;
    }

    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!publicKey) {
        return false;
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    bool valid = false;
    if (context
        && EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, publicKey) > 0
        && EVP_DigestVerifyUpdate(context, payload.constData(),
                                  static_cast<size_t>(payload.size())) > 0) {
        valid = EVP_DigestVerifyFinal(
                    context,
                    reinterpret_cast<const unsigned char*>(signature.constData()),
                    static_cast<size_t>(signature.size())) == 1;
    }

    EVP_MD_CTX_free(context);
    EVP_PKEY_free(publicKey);
    return valid;
}

} // namespace licensing
