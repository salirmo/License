#include <HardwareFingerprint.h>
#include <LicenseValidator.h>

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

Component informational(const QString& name, const QString& value) {
    return {name, value, Role::Informational};
}

QList<Component> hardenedComponents() {
    return {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555")),
        strong(QStringLiteral("board_serial"), QStringLiteral("BOARD-A-123")),
        secondary(QStringLiteral("disk_serial"), QStringLiteral("DISK-A-123")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("abcdef0123456789abcdef0123456789")),
        informational(QStringLiteral("cpu_model"), QStringLiteral("Example CPU")),
        informational(QStringLiteral("bios_version"), QStringLiteral("BIOS 1.0")),
        informational(QStringLiteral("mac"), QStringLiteral("00:11:22:33:44:55")),
        informational(QStringLiteral("os"), QStringLiteral("Example Linux;x86_64"))
    };
}

QList<Component> legacyComponents() {
    return {
        secondary(QStringLiteral("mb_uuid"), QStringLiteral("BOARD-A-123")),
        secondary(QStringLiteral("bios_serial"), QStringLiteral("BIOS 1.0")),
        secondary(QStringLiteral("system_uuid"),
                  QStringLiteral("11111111-2222-3333-4444-555555555555")),
        secondary(QStringLiteral("machine_guid"),
                  QStringLiteral("abcdef0123456789abcdef0123456789")),
        secondary(QStringLiteral("cpu_id"), QStringLiteral("Example CPU")),
        secondary(QStringLiteral("disk_serial"), QStringLiteral("DISK-A-123")),
        informational(QStringLiteral("mac"), QStringLiteral("00:11:22:33:44:55")),
        informational(QStringLiteral("os"), QStringLiteral("Example Linux;x86_64"))
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

QList<Component> without(QList<Component> components, const QString& name) {
    components.erase(
        std::remove_if(components.begin(), components.end(),
                       [&name](const Component& component) {
                           return component.name == name;
                       }),
        components.end());
    return components;
}

QJsonArray componentsJson(const QList<Component>& components, int policyVersion) {
    QJsonArray result;
    for (const Component& component : components) {
        QJsonObject object;
        object.insert(QStringLiteral("name"), component.name);
        object.insert(QStringLiteral("value"), component.value);
        object.insert(QStringLiteral("stable"),
                      HardwareFingerprint::isBindingRole(component.role));
        if (policyVersion >= HardwareFingerprint::HardenedPolicyVersion) {
            object.insert(QStringLiteral("role"),
                          HardwareFingerprint::roleName(component.role));
        }
        result.append(object);
    }
    return result;
}

} // namespace

class HardwareFingerprintTests : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();

    void policyClassifiesComponents();
    void policyHashTestVector();
    void exactFingerprintMatch();
    void zeroMismatches();
    void oneMismatch();
    void twoMismatches();
    void missingComponent();
    void newlyIntroducedComponent();
    void insufficientIdentifiers();
    void emptyFingerprint();
    void sameCpuModelCannotProveMachine();
    void cpuModelChange();
    void macChange();
    void biosUpdate();
    void linuxReinstall();
    void diskReplacement();
    void deterministicRootDiskSelection();
    void motherboardReplacement();
    void differentPhysicalMachine();
    void oldLicenseWithNewClient();
    void newFingerprintPolicyVersion();
    void unsupportedFingerprintPolicyVersion();
    void malformedAndDefaultIdentifiers();

private:
    License licenseFor(const HardwareFingerprint& reference) const;
    QByteArray signedKey(const License& license) const;
    QByteArray sign(const QByteArray& payload) const;
    ValidationError validate(const License& license,
                             const HardwareFingerprint& current,
                             License* output = nullptr) const;

    EVP_PKEY* m_privateKey = nullptr;
    QByteArray m_publicKeyPem;
};

void HardwareFingerprintTests::initTestCase() {
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

void HardwareFingerprintTests::cleanupTestCase() {
    EVP_PKEY_free(m_privateKey);
    m_privateKey = nullptr;
}

License HardwareFingerprintTests::licenseFor(
    const HardwareFingerprint& reference) const {
    License license;
    license.version = 1;
    license.licenseId = QStringLiteral("test-license-id");
    license.product = QStringLiteral("MyApp");
    license.owner = QStringLiteral("Test Owner");
    license.issueDate = QDateTime::currentDateTimeUtc().addSecs(-30);
    license.fingerprintPolicyVersion = reference.policyVersion();
    license.fingerprintHash = reference.fingerprintHash();
    license.fingerprintComponents =
        reference.toJson().value(QStringLiteral("components")).toArray();
    license.nonce = QStringLiteral("test-nonce");
    return license;
}

QByteArray HardwareFingerprintTests::sign(const QByteArray& payload) const {
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

QByteArray HardwareFingerprintTests::signedKey(const License& license) const {
    const QByteArray signature = sign(license.canonical());
    if (signature.isEmpty()) {
        return {};
    }

    QJsonObject root;
    root.insert(QStringLiteral("payload"), license.toJson());
    root.insert(QStringLiteral("signature"),
                QString::fromLatin1(signature.toBase64()));
    root.insert(QStringLiteral("format"), QStringLiteral("acme-license-1"));
    return QJsonDocument(root).toJson(QJsonDocument::Compact).toBase64();
}

ValidationError HardwareFingerprintTests::validate(
    const License& license,
    const HardwareFingerprint& current,
    License* output) const {
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

    License localOutput;
    return validator.validateData(signedKey(license),
                                  output ? *output : localOutput);
}

void HardwareFingerprintTests::policyClassifiesComponents() {
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("system_uuid"), 2),
             Role::Strong);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("board_serial"), 2),
             Role::Strong);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("disk_serial"), 2),
             Role::Secondary);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("machine_id"), 2),
             Role::Secondary);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("cpu_model"), 2),
             Role::Informational);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("bios_version"), 2),
             Role::Informational);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("mac"), 2),
             Role::Informational);
    QCOMPARE(HardwareFingerprint::componentRole(
                 QStringLiteral("os"), 2),
             Role::Informational);
}

void HardwareFingerprintTests::policyHashTestVector() {
    const QList<Component> components = {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("abcdef0123456789abcdef0123456789"))
    };
    const HardwareFingerprint fingerprint = HardwareFingerprint::fromComponents(
        2, components);
    QCOMPARE(fingerprint.fingerprintHash(),
             QStringLiteral(
                 "4a8d0da186917140f082f67c5b609deb66d5ffe3452812835f7c9970fc998d26"));
}

void HardwareFingerprintTests::exactFingerprintMatch() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QVERIFY(reference.isSufficient());
    QVERIFY(validate(licenseFor(reference), reference)
            == ValidationError::None);
}

void HardwareFingerprintTests::zeroMismatches() {
    const QList<Component> referenceComponents = {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("abcdef0123456789abcdef0123456789"))
    };
    QList<Component> currentComponents = referenceComponents;
    currentComponents.append(
        secondary(QStringLiteral("disk_serial"), QStringLiteral("DISK-NEW")));

    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, referenceComponents);
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, currentComponents);
    const auto result = current.match(reference.components(), 1);
    QCOMPARE(result.mismatches, 0);
    QVERIFY(result.valid);
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::oneMismatch() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, withValue(hardenedComponents(), QStringLiteral("board_serial"),
                     QStringLiteral("BOARD-B-999")));
    const auto result = current.match(reference.components(), 1);
    QCOMPARE(result.mismatches, 1);
    QVERIFY(result.strongMatches >= 1);
    QVERIFY(result.valid);
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::twoMismatches() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QList<Component> changed = withValue(
        hardenedComponents(), QStringLiteral("disk_serial"),
        QStringLiteral("DISK-B-999"));
    changed = withValue(changed, QStringLiteral("machine_id"),
                        QStringLiteral("0123456789abcdef0123456789abcdef"));
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(2, changed);
    const auto result = current.match(reference.components(), 1);
    QCOMPARE(result.mismatches, 2);
    QVERIFY(!result.valid);
    QVERIFY(validate(licenseFor(reference), current)
            == ValidationError::FingerprintMismatch);
}

void HardwareFingerprintTests::missingComponent() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint oneMissing = HardwareFingerprint::fromComponents(
        2, without(hardenedComponents(), QStringLiteral("disk_serial")));
    QCOMPARE(oneMissing.match(reference.components(), 1).mismatches, 1);
    QVERIFY(validate(licenseFor(reference), oneMissing)
            == ValidationError::None);

    QList<Component> twoMissing = without(
        hardenedComponents(), QStringLiteral("disk_serial"));
    twoMissing = without(twoMissing, QStringLiteral("machine_id"));
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(2, twoMissing);
    QVERIFY(validate(licenseFor(reference), current)
            == ValidationError::FingerprintMismatch);
}

void HardwareFingerprintTests::newlyIntroducedComponent() {
    const QList<Component> oldComponents = {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("abcdef0123456789abcdef0123456789"))
    };
    QList<Component> newComponents = oldComponents;
    newComponents.append(
        strong(QStringLiteral("board_serial"), QStringLiteral("BOARD-A-123")));
    newComponents.append(
        secondary(QStringLiteral("disk_serial"), QStringLiteral("DISK-A-123")));

    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(2, oldComponents);
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(2, newComponents);
    QVERIFY(reference.fingerprintHash() != current.fingerprintHash());
    QCOMPARE(current.match(reference.components(), 1).mismatches, 0);
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::insufficientIdentifiers() {
    const QList<Component> components = {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555"))
    };
    const HardwareFingerprint insufficient = HardwareFingerprint::fromComponents(2, components);
    QVERIFY(!insufficient.isSufficient());
    QVERIFY(insufficient.fingerprintHash().isEmpty());

    License license;
    license.version = 1;
    license.licenseId = QStringLiteral("insufficient");
    license.product = QStringLiteral("MyApp");
    license.issueDate = QDateTime::currentDateTimeUtc().addSecs(-30);
    license.fingerprintPolicyVersion = 2;
    license.fingerprintHash = QString(64, QLatin1Char('a'));
    license.fingerprintComponents = componentsJson(components, 2);
    license.nonce = QStringLiteral("nonce");

    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QVERIFY(validate(license, current)
            == ValidationError::FingerprintInsufficient);

    const HardwareFingerprint validReference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QVERIFY(validate(licenseFor(validReference), insufficient)
            == ValidationError::FingerprintInsufficient);
}

void HardwareFingerprintTests::emptyFingerprint() {
    License license;
    license.version = 1;
    license.licenseId = QStringLiteral("empty");
    license.product = QStringLiteral("MyApp");
    license.issueDate = QDateTime::currentDateTimeUtc().addSecs(-30);
    license.fingerprintPolicyVersion = 2;
    license.fingerprintHash.clear();
    license.fingerprintComponents = {};
    license.nonce = QStringLiteral("nonce");

    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QVERIFY(validate(license, current) == ValidationError::MalformedPayload);
}

void HardwareFingerprintTests::sameCpuModelCannotProveMachine() {
    const QList<Component> referenceComponents = {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("11111111-2222-3333-4444-555555555555")),
        secondary(QStringLiteral("disk_serial"), QStringLiteral("SHARED-DISK")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("abcdef0123456789abcdef0123456789")),
        informational(QStringLiteral("cpu_model"), QStringLiteral("Same CPU Model"))
    };
    QList<Component> currentComponents = withValue(
        referenceComponents, QStringLiteral("system_uuid"),
        QStringLiteral("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, referenceComponents);
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, currentComponents);
    const auto result = current.match(reference.components(), 1);
    QCOMPARE(result.mismatches, 1);
    QCOMPARE(result.strongMatches, 0);
    QVERIFY(!result.valid);
    QVERIFY(validate(licenseFor(reference), current)
            == ValidationError::FingerprintMismatch);
}

void HardwareFingerprintTests::cpuModelChange() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, withValue(hardenedComponents(), QStringLiteral("cpu_model"),
                     QStringLiteral("Different CPU Model")));
    QCOMPARE(reference.fingerprintHash(), current.fingerprintHash());
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::macChange() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, withValue(hardenedComponents(), QStringLiteral("mac"),
                     QStringLiteral("aa:bb:cc:dd:ee:ff")));
    QCOMPARE(reference.fingerprintHash(), current.fingerprintHash());
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::biosUpdate() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, withValue(hardenedComponents(), QStringLiteral("bios_version"),
                     QStringLiteral("BIOS 2.0")));
    QCOMPARE(reference.fingerprintHash(), current.fingerprintHash());
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::linuxReinstall() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, withValue(hardenedComponents(), QStringLiteral("machine_id"),
                     QStringLiteral("0123456789abcdef0123456789abcdef")));
    QCOMPARE(current.match(reference.components(), 1).mismatches, 1);
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::diskReplacement() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, withValue(hardenedComponents(), QStringLiteral("disk_serial"),
                     QStringLiteral("DISK-B-999")));
    QCOMPARE(current.match(reference.components(), 1).mismatches, 1);
    QVERIFY(validate(licenseFor(reference), current) == ValidationError::None);
}

void HardwareFingerprintTests::deterministicRootDiskSelection() {
    const QByteArray lsblkJson = R"JSON(
{
  "blockdevices": [
    {
      "name": "/dev/sda",
      "type": "disk",
      "serial": "NOT-ROOT",
      "mountpoint": null,
      "children": [
        {"name": "/dev/sda1", "type": "part", "serial": null,
         "mountpoint": "/home"}
      ]
    },
    {
      "name": "/dev/nvme0n1",
      "type": "disk",
      "serial": "ROOT-SERIAL-42",
      "mountpoint": null,
      "children": [
        {"name": "/dev/nvme0n1p2", "type": "part", "serial": null,
         "mountpoint": null,
         "children": [
           {"name": "/dev/mapper/root", "type": "crypt", "serial": null,
            "mountpoint": "/"}
         ]}
      ]
    }
  ]
}
)JSON";

    QCOMPARE(HardwareFingerprint::rootDiskSerialFromLsblkJson(lsblkJson),
             QStringLiteral("root-serial-42"));

    QByteArray sourceOnlyJson = lsblkJson;
    sourceOnlyJson.replace("\"mountpoint\": \"/\"",
                           "\"mountpoint\": null");
    QCOMPARE(HardwareFingerprint::rootDiskSerialFromLsblkJson(
                 sourceOnlyJson, QStringLiteral("/dev/mapper/root")),
             QStringLiteral("root-serial-42"));

    const QByteArray multiDiskRoot = R"JSON(
{
  "blockdevices": [
    {"name":"/dev/sdz", "type":"disk", "serial":"SERIAL-Z",
     "children":[{"name":"/dev/sdz1", "type":"part", "mountpoint":"/"}]},
    {"name":"/dev/sda", "type":"disk", "serial":"SERIAL-A",
     "children":[{"name":"/dev/sda1", "type":"part", "mountpoint":"/"}]}
  ]
}
)JSON";
    QCOMPARE(HardwareFingerprint::rootDiskSerialFromLsblkJson(multiDiskRoot),
             QStringLiteral("serial-a|serial-z"));
    QVERIFY(HardwareFingerprint::rootDiskSerialFromLsblkJson(
                QByteArrayLiteral("{not-json"))
                .isEmpty());
}

void HardwareFingerprintTests::motherboardReplacement() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QList<Component> changed = withValue(
        hardenedComponents(), QStringLiteral("system_uuid"),
        QStringLiteral("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    changed = withValue(changed, QStringLiteral("board_serial"),
                        QStringLiteral("BOARD-B-999"));
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(2, changed);
    const auto result = current.match(reference.components(), 1);
    QCOMPARE(result.mismatches, 2);
    QCOMPARE(result.strongMatches, 0);
    QVERIFY(validate(licenseFor(reference), current)
            == ValidationError::FingerprintMismatch);
}

void HardwareFingerprintTests::differentPhysicalMachine() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QList<Component> changed = withValue(
        hardenedComponents(), QStringLiteral("system_uuid"),
        QStringLiteral("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    changed = withValue(changed, QStringLiteral("board_serial"),
                        QStringLiteral("BOARD-B-999"));
    changed = withValue(changed, QStringLiteral("disk_serial"),
                        QStringLiteral("DISK-B-999"));
    changed = withValue(changed, QStringLiteral("machine_id"),
                        QStringLiteral("0123456789abcdef0123456789abcdef"));
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(2, changed);
    QCOMPARE(current.match(reference.components(), 1).mismatches, 4);
    QVERIFY(validate(licenseFor(reference), current)
            == ValidationError::FingerprintMismatch);
}

void HardwareFingerprintTests::oldLicenseWithNewClient() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        1, legacyComponents());
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        1, withValue(legacyComponents(), QStringLiteral("disk_serial"),
                     QStringLiteral("DISK-B-999")));
    License legacyLicense = licenseFor(reference);
    QCOMPARE(legacyLicense.fingerprintPolicyVersion, 1);
    QVERIFY(!legacyLicense.toJson()
                 .value(QStringLiteral("fingerprint"))
                 .toObject()
                 .contains(QStringLiteral("policy_version")));
    QVERIFY(validate(legacyLicense, current) == ValidationError::None);
}

void HardwareFingerprintTests::newFingerprintPolicyVersion() {
    const HardwareFingerprint reference = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    License license = licenseFor(reference);
    QCOMPARE(license.fingerprintPolicyVersion, 2);
    QCOMPARE(license.toJson()
                 .value(QStringLiteral("fingerprint"))
                 .toObject()
                 .value(QStringLiteral("policy_version"))
                 .toInt(),
             2);

    License output;
    QVERIFY(validate(license, reference, &output) == ValidationError::None);
    QCOMPARE(output.fingerprintPolicyVersion, 2);
}

void HardwareFingerprintTests::unsupportedFingerprintPolicyVersion() {
    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    License license = licenseFor(current);
    license.fingerprintPolicyVersion = 3;
    QVERIFY(validate(license, current)
            == ValidationError::FingerprintPolicyUnsupported);
}

void HardwareFingerprintTests::malformedAndDefaultIdentifiers() {
    const QList<Component> defaults = {
        strong(QStringLiteral("system_uuid"),
               QStringLiteral("00000000-0000-0000-0000-000000000000")),
        strong(QStringLiteral("board_serial"),
               QStringLiteral("To Be Filled By O.E.M.")),
        secondary(QStringLiteral("machine_id"),
                  QStringLiteral("00000000000000000000000000000000"))
    };
    const HardwareFingerprint fingerprint = HardwareFingerprint::fromComponents(2, defaults);
    QVERIFY(!fingerprint.isSufficient());
    QVERIFY(fingerprint.components().isEmpty());

    License license;
    license.version = 1;
    license.licenseId = QStringLiteral("defaults");
    license.product = QStringLiteral("MyApp");
    license.issueDate = QDateTime::currentDateTimeUtc().addSecs(-30);
    license.fingerprintPolicyVersion = 2;
    license.fingerprintHash = QString(64, QLatin1Char('a'));
    license.fingerprintComponents = componentsJson(defaults, 2);
    license.nonce = QStringLiteral("nonce");

    const HardwareFingerprint current = HardwareFingerprint::fromComponents(
        2, hardenedComponents());
    QVERIFY(validate(license, current) == ValidationError::MalformedPayload);
}

QTEST_APPLESS_MAIN(HardwareFingerprintTests)

#include "HardwareFingerprintTests.moc"
