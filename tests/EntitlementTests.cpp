#include <HardwareFingerprint.h>
#include <LicenseValidator.h>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <algorithm>

using licensing::HardwareFingerprint;
using licensing::License;
using licensing::LicenseValidator;
using licensing::ValidationError;

namespace {

using Component = HardwareFingerprint::Component;
using Role = HardwareFingerprint::ComponentRole;

Component strong(const QString& name, const QString& value) {
    return {name, value, Role::Strong};
}

Component secondary(const QString& name, const QString& value) {
    return {name, value, Role::Secondary};
}

QList<Component> hardwareComponents() {
    return {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555")),
        strong(QStringLiteral("board_serial"), QStringLiteral("BOARD-A-123")),
        secondary(QStringLiteral("disk_serial"), QStringLiteral("DISK-A-123")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("abcdef0123456789abcdef0123456789"))
    };
}

QList<Component> withValue(QList<Component> components,
                           const QString& name,
                           const QString& value) {
    for (Component& component : components) {
        if (component.name == name) {
            component.value = value;
        }
    }
    return components;
}

QJsonObject limited(int value) {
    QJsonObject limit;
    limit.insert(QStringLiteral("mode"), QStringLiteral("limited"));
    limit.insert(QStringLiteral("value"), value);
    return limit;
}

QJsonObject unlimited() {
    QJsonObject limit;
    limit.insert(QStringLiteral("mode"), QStringLiteral("unlimited"));
    return limit;
}

QJsonObject module(const QString& id,
                   const QString& displayName,
                   const QJsonObject& cameraLimit) {
    QJsonObject moduleObject;
    moduleObject.insert(QStringLiteral("id"), id);
    if (!displayName.isEmpty()) {
        moduleObject.insert(QStringLiteral("display_name"), displayName);
    }
    moduleObject.insert(QStringLiteral("camera_limit"), cameraLimit);
    return moduleObject;
}

QJsonObject entitlementObject(const QJsonArray& modules,
                              const QJsonObject& userLimit = limited(10)) {
    QJsonObject entitlements;
    entitlements.insert(QStringLiteral("modules"), modules);
    entitlements.insert(QStringLiteral("user_limit"), userLimit);
    return entitlements;
}

} // namespace

class EntitlementTests : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();

    void faceOnly();
    void lprOnly();
    void faceAndLpr();
    void noModules();
    void limitedAndUnlimitedCameraCounts();
    void dynamicModule();
    void multipleDynamicAndFutureModules();
    void duplicateModuleIdRejected();
    void invalidModuleIdRejected();
    void limitedAndUnlimitedUsers();
    void missingModuleReturnsDisabled();
    void malformedLimitRejected();
    void entitlementTamperingCausesSignatureFailure();
    void entitlementsUnavailableBeforeSuccessfulValidation();
    void legacyLicenseWithoutEntitlements();
    void newLicenseWithEntitlements();
    void unsupportedLicenseSchemaVersion();
    void schemaTwoRequiresEntitlements();
    void hardwareFingerprintBehaviorRemainsUnchanged();

private:
    License legacyLicense() const;
    License entitlementLicense(const QJsonValue& entitlements) const;
    QByteArray sign(const QByteArray& payload) const;
    QByteArray signedKey(const License& license) const;
    ValidationError validate(const License& license,
                             const HardwareFingerprint& current,
                             License& output) const;
    ValidationError validateData(const QByteArray& key,
                                 const HardwareFingerprint& current,
                                 License& output) const;

    EVP_PKEY* m_privateKey = nullptr;
    QByteArray m_publicKeyPem;
};

void EntitlementTests::initTestCase() {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    QVERIFY(context != nullptr);
    QVERIFY(EVP_PKEY_keygen_init(context) > 0);
    QVERIFY(EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) > 0);
    QVERIFY(EVP_PKEY_keygen(context, &m_privateKey) > 0);
    EVP_PKEY_CTX_free(context);

    BIO* publicBio = BIO_new(BIO_s_mem());
    QVERIFY(publicBio != nullptr);
    QVERIFY(PEM_write_bio_PUBKEY(publicBio, m_privateKey) == 1);
    char* data = nullptr;
    const long length = BIO_get_mem_data(publicBio, &data);
    QVERIFY(length > 0);
    m_publicKeyPem = QByteArray(data, static_cast<int>(length));
    BIO_free(publicBio);
}

void EntitlementTests::cleanupTestCase() {
    EVP_PKEY_free(m_privateKey);
    m_privateKey = nullptr;
}

License EntitlementTests::legacyLicense() const {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        HardwareFingerprint::HardenedPolicyVersion, hardwareComponents());

    License license;
    license.version = License::LegacySchemaVersion;
    license.licenseId = QStringLiteral("entitlement-test-license");
    license.product = QStringLiteral("MyApp");
    license.owner = QStringLiteral("Test Owner");
    license.issueDate = QDateTime::currentDateTimeUtc().addSecs(-30);
    license.fingerprintPolicyVersion = reference.policyVersion();
    license.fingerprintHash = reference.fingerprintHash();
    license.fingerprintComponents =
        reference.toJson().value(QStringLiteral("components")).toArray();
    license.nonce = QStringLiteral("entitlement-test-nonce");
    return license;
}

License EntitlementTests::entitlementLicense(
    const QJsonValue& entitlements) const {
    QJsonObject payload = legacyLicense().toJson();
    payload.insert(QStringLiteral("version"), License::CurrentSchemaVersion);
    payload.insert(QStringLiteral("entitlements"), entitlements);

    License license;
    const bool parsed = license.fromJson(payload);
    Q_ASSERT(parsed);
    return license;
}

QByteArray EntitlementTests::sign(const QByteArray& payload) const {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        return {};
    }

    QByteArray signature;
    if (EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr,
                           m_privateKey) > 0
        && EVP_DigestSignUpdate(context, payload.constData(),
                                static_cast<size_t>(payload.size())) > 0) {
        size_t signatureLength = 0;
        if (EVP_DigestSignFinal(context, nullptr, &signatureLength) > 0) {
            signature.resize(static_cast<int>(signatureLength));
            if (EVP_DigestSignFinal(
                    context,
                    reinterpret_cast<unsigned char*>(signature.data()),
                    &signatureLength) <= 0) {
                signature.clear();
            } else {
                signature.resize(static_cast<int>(signatureLength));
            }
        }
    }
    EVP_MD_CTX_free(context);
    return signature;
}

QByteArray EntitlementTests::signedKey(const License& license) const {
    QJsonObject envelope;
    envelope.insert(QStringLiteral("payload"), license.toJson());
    envelope.insert(QStringLiteral("signature"),
                    QString::fromLatin1(sign(license.canonical()).toBase64()));
    envelope.insert(QStringLiteral("format"), QStringLiteral("acme-license-1"));
    return QJsonDocument(envelope).toJson(QJsonDocument::Compact).toBase64();
}

ValidationError EntitlementTests::validateData(
    const QByteArray& key,
    const HardwareFingerprint& current,
    License& output) const {
    const int expectedPolicy = current.policyVersion();
    LicenseValidator validator(
        m_publicKeyPem,
        QStringLiteral("MyApp"),
        [current, expectedPolicy](int requestedPolicy) {
            if (requestedPolicy == expectedPolicy) {
                return current;
            }
            return HardwareFingerprint::fromComponents(requestedPolicy, {});
        });
    return validator.validateData(key, output);
}

ValidationError EntitlementTests::validate(
    const License& license,
    const HardwareFingerprint& current,
    License& output) const {
    return validateData(signedKey(license), current, output);
}

void EntitlementTests::faceOnly() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8))
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(output.isModuleEnabled(QStringLiteral("face")));
    QVERIFY(!output.isModuleEnabled(QStringLiteral("lpr")));
}

void EntitlementTests::lprOnly() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("lpr"), QStringLiteral("LPR"), unlimited())
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(output.isModuleEnabled(QStringLiteral("lpr")));
    QVERIFY(!output.isModuleEnabled(QStringLiteral("face")));
}

void EntitlementTests::faceAndLpr() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8)),
        module(QStringLiteral("lpr"), QStringLiteral("LPR"), unlimited())
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(output.isModuleEnabled(QStringLiteral("face")));
    QVERIFY(output.isModuleEnabled(QStringLiteral("lpr")));
    QCOMPARE(output.licensedModules().size(), 2);
}

void EntitlementTests::noModules() {
    const License license = entitlementLicense(entitlementObject({}));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(output.entitlementsAvailable());
    QVERIFY(output.licensedModules().isEmpty());
    QVERIFY(!output.isModuleEnabled(QStringLiteral("face")));
}

void EntitlementTests::limitedAndUnlimitedCameraCounts() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8)),
        module(QStringLiteral("lpr"), QStringLiteral("LPR"), unlimited())
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);

    const licensing::ResourceLimit face =
        output.moduleCameraLimit(QStringLiteral("face"));
    QVERIFY(!face.unlimited);
    QCOMPARE(face.value, 8);
    const licensing::ResourceLimit lpr =
        output.moduleCameraLimit(QStringLiteral("lpr"));
    QVERIFY(lpr.unlimited);
    QCOMPARE(lpr.value, 0);
}

void EntitlementTests::dynamicModule() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("parking"), QStringLiteral("Parking Management"),
               limited(4))
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(output.isModuleEnabled(QStringLiteral("parking")));
    QCOMPARE(output.licensedModules().at(0).displayName,
             QStringLiteral("Parking Management"));
}

void EntitlementTests::multipleDynamicAndFutureModules() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("parking"), QString(), limited(4)),
        module(QStringLiteral("crowd_detection"), QString(), unlimited()),
        module(QStringLiteral("future_module"), QString(), limited(2))
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QCOMPARE(output.licensedModules().size(), 3);
    QVERIFY(output.isModuleEnabled(QStringLiteral("future_module")));
    QVERIFY(output.moduleCameraLimit(QStringLiteral("crowd_detection")).unlimited);
}

void EntitlementTests::duplicateModuleIdRejected() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8)),
        module(QStringLiteral(" FACE "), QStringLiteral("Duplicate"), limited(1))
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::EntitlementsInvalid);
    QVERIFY(!output.entitlementsAvailable());
}

void EntitlementTests::invalidModuleIdRejected() {
    const QStringList invalidIds = {
        QString(), QStringLiteral("2d_camera"),
        QStringLiteral("fire-detection"), QStringLiteral("fire detection"),
        QStringLiteral("_parking"), QStringLiteral("fire__detection"),
        QStringLiteral("other")
    };

    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardwareComponents());
    for (const QString& id : invalidIds) {
        const License license = entitlementLicense(entitlementObject({
            module(id, QString(), limited(1))
        }));
        License output;
        const ValidationError error = validate(license, current, output);
        QVERIFY2(error == ValidationError::EntitlementsInvalid,
                 qPrintable(QStringLiteral("ID '%1' was not rejected").arg(id)));
    }
}

void EntitlementTests::limitedAndUnlimitedUsers() {
    License limitedLicense = entitlementLicense(
        entitlementObject({}, limited(10)));
    License output;
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardwareComponents());
    QCOMPARE(validate(limitedLicense, current, output), ValidationError::None);
    QVERIFY(!output.userLimit().unlimited);
    QCOMPARE(output.userLimit().value, 10);

    const License unlimitedLicense = entitlementLicense(
        entitlementObject({}, unlimited()));
    QCOMPARE(validate(unlimitedLicense, current, output), ValidationError::None);
    QVERIFY(output.userLimit().unlimited);
    QCOMPARE(output.userLimit().value, 0);
}

void EntitlementTests::missingModuleReturnsDisabled() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8))
    }));
    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(!output.isModuleEnabled(QStringLiteral("unknown_module")));
    const licensing::ResourceLimit missing =
        output.moduleCameraLimit(QStringLiteral("unknown_module"));
    QVERIFY(!missing.unlimited);
    QCOMPARE(missing.value, 0);
}

void EntitlementTests::malformedLimitRejected() {
    QList<QJsonObject> malformedLimits;
    malformedLimits.append(limited(0));
    malformedLimits.append(limited(-1));

    QJsonObject fractional = limited(1);
    fractional.insert(QStringLiteral("value"), 1.5);
    malformedLimits.append(fractional);

    QJsonObject missingValue;
    missingValue.insert(QStringLiteral("mode"), QStringLiteral("limited"));
    malformedLimits.append(missingValue);

    QJsonObject ambiguousUnlimited = unlimited();
    ambiguousUnlimited.insert(QStringLiteral("value"), 0);
    malformedLimits.append(ambiguousUnlimited);

    QJsonObject unknownMode;
    unknownMode.insert(QStringLiteral("mode"), QStringLiteral("infinite"));
    malformedLimits.append(unknownMode);

    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardwareComponents());
    for (const QJsonObject& limit : malformedLimits) {
        const License license = entitlementLicense(entitlementObject({
            module(QStringLiteral("face"), QStringLiteral("Face"), limit)
        }));
        License output;
        QCOMPARE(validate(license, current, output),
                 ValidationError::EntitlementsInvalid);
    }

    const License malformedUserLimit = entitlementLicense(
        entitlementObject({}, limited(0)));
    License output;
    QCOMPARE(validate(malformedUserLimit, current, output),
             ValidationError::EntitlementsInvalid);
}

void EntitlementTests::entitlementTamperingCausesSignatureFailure() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8))
    }));
    const QByteArray key = signedKey(license);
    QJsonObject envelope = QJsonDocument::fromJson(
        QByteArray::fromBase64(key)).object();
    QJsonObject payload = envelope.value(QStringLiteral("payload")).toObject();
    QJsonObject entitlements = payload.value(QStringLiteral("entitlements")).toObject();
    QJsonArray modules = entitlements.value(QStringLiteral("modules")).toArray();
    QJsonObject face = modules.at(0).toObject();
    face.insert(QStringLiteral("camera_limit"), limited(999));
    modules.replace(0, face);
    entitlements.insert(QStringLiteral("modules"), modules);
    payload.insert(QStringLiteral("entitlements"), entitlements);
    envelope.insert(QStringLiteral("payload"), payload);
    const QByteArray tampered = QJsonDocument(envelope)
                                    .toJson(QJsonDocument::Compact).toBase64();

    License output;
    QCOMPARE(validateData(tampered, HardwareFingerprint::fromComponents(
                               2, hardwareComponents()), output),
             ValidationError::SignatureInvalid);
    QVERIFY(!output.entitlementsAvailable());
}

void EntitlementTests::entitlementsUnavailableBeforeSuccessfulValidation() {
    const License pending = entitlementLicense(entitlementObject({
        module(QStringLiteral("face"), QStringLiteral("Face"), limited(8))
    }));
    QVERIFY(!pending.entitlementsAvailable());
    QVERIFY(!pending.isModuleEnabled(QStringLiteral("face")));
    QVERIFY(pending.licensedModules().isEmpty());
    QCOMPARE(pending.userLimit().value, 0);

    License output;
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardwareComponents());
    QCOMPARE(validate(pending, current, output), ValidationError::None);
    QVERIFY(output.entitlementsAvailable());

    QByteArray invalidKey = signedKey(pending);
    QJsonObject envelope = QJsonDocument::fromJson(
        QByteArray::fromBase64(invalidKey)).object();
    envelope.insert(QStringLiteral("signature"), QStringLiteral("AAAA"));
    invalidKey = QJsonDocument(envelope).toJson(QJsonDocument::Compact).toBase64();
    QCOMPARE(validateData(invalidKey, current, output),
             ValidationError::SignatureInvalid);
    QVERIFY(!output.entitlementsAvailable());
    QVERIFY(!output.isModuleEnabled(QStringLiteral("face")));
}

void EntitlementTests::legacyLicenseWithoutEntitlements() {
    const License legacy = legacyLicense();
    QVERIFY(!legacy.toJson().contains(QStringLiteral("entitlements")));

    License output;
    QCOMPARE(validate(legacy, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(!output.entitlementsAvailable());
    QVERIFY(!output.isModuleEnabled(QStringLiteral("face")));
    QVERIFY(output.licensedModules().isEmpty());
    QCOMPARE(output.userLimit().value, 0);
}

void EntitlementTests::newLicenseWithEntitlements() {
    const License license = entitlementLicense(entitlementObject({
        module(QStringLiteral("future_module"), QStringLiteral("Future Module"),
               unlimited())
    }, unlimited()));
    QCOMPARE(license.version, License::CurrentSchemaVersion);
    QVERIFY(license.toJson().contains(QStringLiteral("entitlements")));

    License output;
    QCOMPARE(validate(license, HardwareFingerprint::fromComponents(
                          2, hardwareComponents()), output),
             ValidationError::None);
    QVERIFY(output.entitlementsAvailable());
    QVERIFY(output.isModuleEnabled(QStringLiteral("future_module")));
}

void EntitlementTests::unsupportedLicenseSchemaVersion() {
    QJsonObject payload = legacyLicense().toJson();
    payload.insert(QStringLiteral("version"), 99);
    QJsonObject envelope;
    envelope.insert(QStringLiteral("format"), QStringLiteral("acme-license-1"));
    envelope.insert(QStringLiteral("payload"), payload);
    envelope.insert(QStringLiteral("signature"), QStringLiteral("AAAA"));

    License output;
    QCOMPARE(validateData(
                 QJsonDocument(envelope).toJson(QJsonDocument::Compact).toBase64(),
                 HardwareFingerprint::fromComponents(2, hardwareComponents()),
                 output),
             ValidationError::LicenseVersionUnsupported);
}

void EntitlementTests::schemaTwoRequiresEntitlements() {
    QJsonObject payload = legacyLicense().toJson();
    payload.insert(QStringLiteral("version"), License::CurrentSchemaVersion);
    QJsonObject envelope;
    envelope.insert(QStringLiteral("format"), QStringLiteral("acme-license-1"));
    envelope.insert(QStringLiteral("payload"), payload);
    envelope.insert(QStringLiteral("signature"), QStringLiteral("AAAA"));

    License output;
    QCOMPARE(validateData(
                 QJsonDocument(envelope).toJson(QJsonDocument::Compact).toBase64(),
                 HardwareFingerprint::fromComponents(2, hardwareComponents()),
                 output),
             ValidationError::MalformedPayload);
}

void EntitlementTests::hardwareFingerprintBehaviorRemainsUnchanged() {
    const License license = entitlementLicense(entitlementObject({}));
    const HardwareFingerprint oneChange = HardwareFingerprint::fromComponents(
        2, withValue(hardwareComponents(), QStringLiteral("disk_serial"),
                     QStringLiteral("DISK-B-999")));
    License output;
    QCOMPARE(validate(license, oneChange, output), ValidationError::None);
    QVERIFY(output.entitlementsAvailable());

    QList<Component> changed = withValue(
        hardwareComponents(), QStringLiteral("disk_serial"),
        QStringLiteral("DISK-B-999"));
    changed = withValue(changed, QStringLiteral("machine_id"),
                        QStringLiteral("0123456789abcdef0123456789abcdef"));
    const HardwareFingerprint twoChanges = HardwareFingerprint::fromComponents(
        2, changed);
    QCOMPARE(validate(license, twoChanges, output),
             ValidationError::FingerprintMismatch);
    QVERIFY(!output.entitlementsAvailable());

    QJsonObject malformed = entitlementObject({});
    malformed.insert(QStringLiteral("user_limit"), limited(0));
    const License malformedLicense = entitlementLicense(malformed);
    QCOMPARE(validate(malformedLicense, twoChanges, output),
             ValidationError::FingerprintMismatch);
}

QTEST_APPLESS_MAIN(EntitlementTests)

#include "EntitlementTests.moc"
