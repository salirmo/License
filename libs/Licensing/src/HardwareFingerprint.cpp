#include "HardwareFingerprint.h"

#include "CryptoManager.h"

#include <QFile>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QNetworkInterface>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QSysInfo>

#include <algorithm>

namespace licensing {
namespace {

using Component = HardwareFingerprint::Component;
using ComponentRole = HardwareFingerprint::ComponentRole;

const QSet<QString>& invalidIdentifierValues() {
    static const QSet<QString> values = {
        QStringLiteral("0"),
        QStringLiteral("na"),
        QStringLiteral("n/a"),
        QStringLiteral("none"),
        QStringLiteral("null"),
        QStringLiteral("unknown"),
        QStringLiteral("not set"),
        QStringLiteral("not specified"),
        QStringLiteral("not available"),
        QStringLiteral("not applicable"),
        QStringLiteral("default"),
        QStringLiteral("default string"),
        QStringLiteral("system serial number"),
        QStringLiteral("to be filled by o.e.m."),
        QStringLiteral("to be filled by oem"),
        QStringLiteral("123456789")
    };
    return values;
}

QString compactHex(QString value) {
    value.remove(QLatin1Char('-'));
    value.remove(QLatin1Char('{'));
    value.remove(QLatin1Char('}'));
    value.remove(QLatin1Char(' '));
    return value;
}

bool isRepeatedPlaceholder(const QString& value) {
    QString compact = value;
    compact.remove(QRegularExpression(QStringLiteral("[^a-z0-9]")));
    if (compact.isEmpty()) {
        return true;
    }

    const QChar first = compact.front();
    const bool allSame = std::all_of(compact.cbegin(), compact.cend(),
                                     [first](QChar character) {
                                         return character == first;
                                     });
    return allSame && (first == QLatin1Char('0') || first == QLatin1Char('f'));
}

struct DiskCandidate {
    QString device;
    QString serial;
};

void collectRootDiskCandidates(const QJsonObject& device,
                               const QString& rootSource,
                               QList<DiskCandidate> ancestors,
                               QList<DiskCandidate>& result) {
    if (device.value(QStringLiteral("type")).toString()
        == QStringLiteral("disk")) {
        const QString serial = device.value(QStringLiteral("serial")).toString();
        if (!serial.trimmed().isEmpty()) {
            ancestors.append({
                device.value(QStringLiteral("name")).toString(),
                serial
            });
        }
    }

    const QString deviceName = device.value(QStringLiteral("name")).toString();
    if (device.value(QStringLiteral("mountpoint")).toString()
            == QStringLiteral("/")
        || (!rootSource.isEmpty() && deviceName == rootSource)) {
        result.append(ancestors);
    }

    const QJsonArray children = device.value(QStringLiteral("children")).toArray();
    for (const QJsonValue& child : children) {
        if (child.isObject()) {
            collectRootDiskCandidates(child.toObject(), rootSource,
                                      ancestors, result);
        }
    }
}

} // namespace

HardwareFingerprint::HardwareFingerprint(int policyVersion)
    : m_policyVersion(policyVersion) {
    refresh();
}

HardwareFingerprint::HardwareFingerprint(int policyVersion, SkipRefreshTag)
    : m_policyVersion(policyVersion) {
}

HardwareFingerprint HardwareFingerprint::fromComponents(
    int policyVersion,
    const QList<Component>& components) {
    HardwareFingerprint fingerprint(policyVersion, SkipRefreshTag{});
    for (const Component& component : components) {
        fingerprint.addComponent(component.name, component.value, component.role);
    }
    fingerprint.finalize();
    return fingerprint;
}

bool HardwareFingerprint::isSupportedPolicy(int policyVersion) {
    return policyVersion == LegacyPolicyVersion
           || policyVersion == HardenedPolicyVersion
           || policyVersion == UnprivilegedPolicyVersion;
}

bool HardwareFingerprint::isBindingRole(ComponentRole role) {
    return role == ComponentRole::Strong || role == ComponentRole::Secondary;
}

QString HardwareFingerprint::roleName(ComponentRole role) {
    switch (role) {
    case ComponentRole::Strong:
        return QStringLiteral("strong");
    case ComponentRole::Secondary:
        return QStringLiteral("secondary");
    case ComponentRole::Informational:
        return QStringLiteral("informational");
    case ComponentRole::Unknown:
        break;
    }
    return QStringLiteral("unknown");
}

HardwareFingerprint::ComponentRole HardwareFingerprint::componentRole(
    const QString& name,
    int policyVersion) {
    if (policyVersion == LegacyPolicyVersion) {
        if (name == QStringLiteral("mb_uuid")
            || name == QStringLiteral("bios_serial")
            || name == QStringLiteral("system_uuid")
            || name == QStringLiteral("machine_guid")
            || name == QStringLiteral("cpu_id")
            || name == QStringLiteral("disk_serial")) {
            return ComponentRole::Secondary;
        }
        if (name == QStringLiteral("mac") || name == QStringLiteral("os")) {
            return ComponentRole::Informational;
        }
        return ComponentRole::Unknown;
    }

    if (policyVersion == HardenedPolicyVersion
        || policyVersion == UnprivilegedPolicyVersion) {
        if (name == QStringLiteral("system_uuid")
            || name == QStringLiteral("board_serial")) {
            return ComponentRole::Strong;
        }
        if (name == QStringLiteral("disk_serial")
            || name == QStringLiteral("machine_id")) {
            return ComponentRole::Secondary;
        }
        if (name == QStringLiteral("cpu_model")
            || name == QStringLiteral("bios_version")
            || name == QStringLiteral("mac")
            || name == QStringLiteral("os")) {
            return ComponentRole::Informational;
        }
    }

    return ComponentRole::Unknown;
}

QString HardwareFingerprint::normalizeValue(const QString& name,
                                            const QString& value,
                                            int policyVersion) {
    if (policyVersion == LegacyPolicyVersion) {
        return value.trimmed();
    }
    if (policyVersion != HardenedPolicyVersion
        && policyVersion != UnprivilegedPolicyVersion) {
        return {};
    }

    QString normalized = value.simplified().toLower();
    if (name == QStringLiteral("system_uuid")) {
        const QString compact = compactHex(normalized);
        static const QRegularExpression uuidHex(
            QStringLiteral("^[0-9a-f]{32}$"));
        if (!uuidHex.match(compact).hasMatch()) {
            return normalized;
        }
        return compact.mid(0, 8) + QLatin1Char('-')
               + compact.mid(8, 4) + QLatin1Char('-')
               + compact.mid(12, 4) + QLatin1Char('-')
               + compact.mid(16, 4) + QLatin1Char('-')
               + compact.mid(20, 12);
    }
    if (name == QStringLiteral("machine_id")) {
        return compactHex(normalized);
    }
    if (name == QStringLiteral("mac")) {
        QStringList addresses;
        const QStringList values = normalized.split(QLatin1Char(','),
                                                     Qt::SkipEmptyParts);
        for (const QString& address : values) {
            const QString candidate = address.trimmed().toLower();
            if (!candidate.isEmpty() && !addresses.contains(candidate)) {
                addresses.append(candidate);
            }
        }
        addresses.sort();
        return addresses.join(QLatin1Char(','));
    }
    return normalized;
}

bool HardwareFingerprint::isUsableValue(const QString& name,
                                        const QString& normalizedValue,
                                        int policyVersion) {
    if (normalizedValue.isEmpty()) {
        return false;
    }
    if (policyVersion == LegacyPolicyVersion) {
        return true;
    }
    if ((policyVersion != HardenedPolicyVersion
         && policyVersion != UnprivilegedPolicyVersion)
        || componentRole(name, policyVersion) == ComponentRole::Unknown) {
        return false;
    }

    if (!isBindingRole(componentRole(name, policyVersion))) {
        return true;
    }
    if (invalidIdentifierValues().contains(normalizedValue)
        || isRepeatedPlaceholder(normalizedValue)) {
        return false;
    }

    if (name == QStringLiteral("system_uuid")) {
        static const QRegularExpression uuid(
            QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));
        return uuid.match(normalizedValue).hasMatch();
    }
    if (name == QStringLiteral("machine_id")) {
        static const QRegularExpression machineId(
            QStringLiteral("^[0-9a-f]{32}$"));
        return machineId.match(normalizedValue).hasMatch();
    }

    static const QRegularExpression usefulCharacter(QStringLiteral("[a-z0-9]"));
    return normalizedValue.size() >= 3
           && usefulCharacter.match(normalizedValue).hasMatch();
}

void HardwareFingerprint::addComponent(const QString& name,
                                       const QString& value,
                                       ComponentRole role) {
    const QString normalizedName = name.trimmed();
    const ComponentRole expectedRole = componentRole(normalizedName, m_policyVersion);
    if (expectedRole == ComponentRole::Unknown || role != expectedRole) {
        return;
    }

    const QString normalizedValue = normalizeValue(normalizedName, value,
                                                   m_policyVersion);
    if (!isUsableValue(normalizedName, normalizedValue, m_policyVersion)) {
        return;
    }

    const auto duplicate = std::find_if(
        m_components.cbegin(), m_components.cend(),
        [&normalizedName](const Component& component) {
            return component.name == normalizedName;
        });
    if (duplicate == m_components.cend()) {
        m_components.append({normalizedName, normalizedValue, expectedRole});
    }
}

void HardwareFingerprint::refresh() {
    m_components.clear();
    m_fingerprintHash.clear();
    m_error.clear();

    if (m_policyVersion == LegacyPolicyVersion) {
        addComponent(QStringLiteral("mb_uuid"), readBoardSerial(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("bios_serial"), readBiosVersion(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("system_uuid"), readSystemUuid(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("machine_guid"), readMachineId(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("cpu_id"), readCpuModel(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("disk_serial"), readLegacyPrimaryDiskSerial(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("mac"), readMacAddresses(),
                     ComponentRole::Informational);
        addComponent(QStringLiteral("os"), readOsInfo(),
                     ComponentRole::Informational);
    } else if (m_policyVersion == HardenedPolicyVersion
               || m_policyVersion == UnprivilegedPolicyVersion) {
        addComponent(QStringLiteral("system_uuid"), readSystemUuid(),
                     ComponentRole::Strong);
        addComponent(QStringLiteral("board_serial"), readBoardSerial(),
                     ComponentRole::Strong);
        addComponent(QStringLiteral("disk_serial"), readRootDiskSerial(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("machine_id"), readMachineId(),
                     ComponentRole::Secondary);
        addComponent(QStringLiteral("cpu_model"), readCpuModel(),
                     ComponentRole::Informational);
        addComponent(QStringLiteral("bios_version"), readBiosVersion(),
                     ComponentRole::Informational);
        addComponent(QStringLiteral("mac"), readMacAddresses(),
                     ComponentRole::Informational);
        addComponent(QStringLiteral("os"), readOsInfo(),
                     ComponentRole::Informational);
    }

    finalize();
}

void HardwareFingerprint::finalize() {
    m_fingerprintHash.clear();
    m_error.clear();

    if (!isSupportedPolicy(m_policyVersion)) {
        m_error = QStringLiteral("Unsupported hardware fingerprint policy.");
        return;
    }
    if ((m_policyVersion == HardenedPolicyVersion
         || m_policyVersion == UnprivilegedPolicyVersion)
        && !hasSufficientIdentifiers(m_components, m_policyVersion)) {
        int strongCount = 0;
        int bindingCount = 0;
        QSet<QString> bindingNames;
        for (const Component& component : m_components) {
            if (component.role == ComponentRole::Strong) {
                ++strongCount;
            }
            if (isBindingRole(component.role)) {
                ++bindingCount;
                bindingNames.insert(component.name);
            }
        }
        if (m_policyVersion == HardenedPolicyVersion) {
            m_error = QStringLiteral(
                "Fingerprint policy 2 requires at least one strong identifier "
                "and at least two total binding identifiers. Found %1 strong "
                "and %2 total binding identifiers.")
                          .arg(strongCount)
                          .arg(bindingCount);
        } else {
            const int requiredCount =
                (bindingNames.contains(QStringLiteral("disk_serial")) ? 1 : 0)
                + (bindingNames.contains(QStringLiteral("machine_id")) ? 1 : 0);
            m_error = QStringLiteral(
                "Fingerprint policy 3 requires an unprivileged root-disk "
                "serial and Linux machine-id. Found %1 of 2 required "
                "identifiers.")
                          .arg(requiredCount);
        }
        return;
    }

    m_fingerprintHash = calculateHash(m_components, m_policyVersion);
    if (m_fingerprintHash.isEmpty()) {
        m_error = QStringLiteral("No usable hardware identifiers are available.");
    }
}

int HardwareFingerprint::policyVersion() const {
    return m_policyVersion;
}

bool HardwareFingerprint::isSufficient() const {
    return m_error.isEmpty() && !m_fingerprintHash.isEmpty();
}

QString HardwareFingerprint::errorString() const {
    return m_error;
}

QString HardwareFingerprint::fingerprintHash() const {
    return m_fingerprintHash;
}

QList<HardwareFingerprint::Component> HardwareFingerprint::components() const {
    return m_components;
}

QJsonObject HardwareFingerprint::toJson() const {
    if (!isSufficient()) {
        return {};
    }

    QJsonArray componentsJson;
    for (const Component& component : m_components) {
        QJsonObject object;
        object.insert(QStringLiteral("name"), component.name);
        object.insert(QStringLiteral("value"), component.value);
        object.insert(QStringLiteral("stable"), isBindingRole(component.role));
        if (m_policyVersion >= HardenedPolicyVersion) {
            object.insert(QStringLiteral("role"), roleName(component.role));
        }
        componentsJson.append(object);
    }

    QJsonObject result;
    if (m_policyVersion >= HardenedPolicyVersion) {
        result.insert(QStringLiteral("policy_version"), m_policyVersion);
    }
    result.insert(QStringLiteral("hash"), m_fingerprintHash);
    result.insert(QStringLiteral("components"), componentsJson);
    return result;
}

bool HardwareFingerprint::hasSufficientIdentifiers(
    const QList<Component>& components,
    int policyVersion) {
    if (policyVersion == LegacyPolicyVersion) {
        return true;
    }
    if (policyVersion != HardenedPolicyVersion
        && policyVersion != UnprivilegedPolicyVersion) {
        return false;
    }

    QSet<QString> bindingNames;
    QSet<QString> strongNames;
    for (const Component& component : components) {
        if (!isUsableValue(component.name, component.value, policyVersion)) {
            continue;
        }
        if (isBindingRole(component.role)) {
            bindingNames.insert(component.name);
        }
        if (component.role == ComponentRole::Strong) {
            strongNames.insert(component.name);
        }
    }
    if (policyVersion == HardenedPolicyVersion) {
        return !strongNames.isEmpty()
               && bindingNames.size() >= MinimumBindingIdentifiers;
    }

    // These two identifiers are readable by a normal Linux process. Requiring
    // both makes policy-3 fingerprints device-specific without depending on a
    // privileged DMI file or an administrator authorization dialog.
    return bindingNames.contains(QStringLiteral("disk_serial"))
           && bindingNames.contains(QStringLiteral("machine_id"));
}

QString HardwareFingerprint::calculateHash(const QList<Component>& components,
                                           int policyVersion) {
    if (!isSupportedPolicy(policyVersion)
        || ((policyVersion == HardenedPolicyVersion
             || policyVersion == UnprivilegedPolicyVersion)
            && !hasSufficientIdentifiers(components, policyVersion))) {
        return {};
    }

    QStringList componentHashes;
    for (const Component& component : components) {
        if (!isBindingRole(component.role)) {
            continue;
        }
        const QByteArray value = (component.name + QLatin1Char(':')
                                  + component.value).toUtf8();
        componentHashes.append(QString::fromLatin1(
            CryptoManager::sha256(value).toHex()));
    }
    componentHashes.sort();
    return QString::fromLatin1(
        CryptoManager::sha256(componentHashes.join(QLatin1Char('|')).toUtf8())
            .toHex());
}

HardwareFingerprint::MatchResult HardwareFingerprint::evaluateMatch(
    const QList<Component>& current,
    const QList<Component>& reference,
    int policyVersion,
    int tolerance) {
    MatchResult result;
    if (!isSupportedPolicy(policyVersion) || tolerance < 0) {
        return result;
    }
    if ((policyVersion == HardenedPolicyVersion
         || policyVersion == UnprivilegedPolicyVersion)
        && (!hasSufficientIdentifiers(current, policyVersion)
            || !hasSufficientIdentifiers(reference, policyVersion))) {
        return result;
    }

    QHash<QString, Component> currentComponents;
    for (const Component& component : current) {
        if (isBindingRole(component.role)) {
            currentComponents.insert(component.name, component);
        }
    }

    for (const Component& component : reference) {
        if (!isBindingRole(component.role)) {
            continue;
        }

        const auto currentComponent = currentComponents.constFind(component.name);
        if (currentComponent != currentComponents.cend()
            && currentComponent->value == component.value) {
            ++result.bindingMatches;
            if (component.role == ComponentRole::Strong
                && currentComponent->role == ComponentRole::Strong) {
                ++result.strongMatches;
            }
        } else if (policyVersion == UnprivilegedPolicyVersion
                   && (component.name == QStringLiteral("system_uuid")
                       || component.name == QStringLiteral("board_serial"))
                   && currentComponent == currentComponents.cend()) {
            // DMI values are optional enhancements in policy 3. If Linux later
            // hides them, losing permission must not invalidate the license.
            continue;
        } else {
            ++result.mismatches;
        }
    }

    const bool requiredMatch =
        policyVersion == HardenedPolicyVersion
            ? result.strongMatches > 0
            : result.bindingMatches > 0;
    result.valid = requiredMatch && result.mismatches <= tolerance;
    return result;
}

HardwareFingerprint::MatchResult HardwareFingerprint::match(
    const QList<Component>& reference,
    int tolerance) const {
    return evaluateMatch(m_components, reference, m_policyVersion, tolerance);
}

bool HardwareFingerprint::tolerantMatch(const QList<Component>& reference,
                                        int tolerance) const {
    return match(reference, tolerance).valid;
}

bool HardwareFingerprint::parseComponents(const QJsonArray& json,
                                          int policyVersion,
                                          QList<Component>& components,
                                          QString* error) {
    components.clear();
    auto fail = [error](const QString& message) {
        if (error) {
            *error = message;
        }
        return false;
    };

    if (!isSupportedPolicy(policyVersion) || json.isEmpty()) {
        return fail(QStringLiteral("The fingerprint policy or component list is invalid."));
    }

    QSet<QString> names;
    for (const QJsonValue& value : json) {
        if (!value.isObject()) {
            return fail(QStringLiteral("A fingerprint component is not an object."));
        }
        const QJsonObject object = value.toObject();
        if (!object.value(QStringLiteral("name")).isString()
            || !object.value(QStringLiteral("value")).isString()) {
            return fail(QStringLiteral("A fingerprint component has invalid fields."));
        }

        const QString name = object.value(QStringLiteral("name")).toString().trimmed();
        const QString rawValue = object.value(QStringLiteral("value")).toString();
        if (name.isEmpty() || names.contains(name)) {
            return fail(QStringLiteral("A fingerprint component name is empty or duplicated."));
        }

        ComponentRole role = ComponentRole::Unknown;
        if (policyVersion == LegacyPolicyVersion) {
            role = object.value(QStringLiteral("stable")).toBool()
                       ? ComponentRole::Secondary
                       : ComponentRole::Informational;
        } else {
            const ComponentRole expected = componentRole(name, policyVersion);
            if (expected == ComponentRole::Unknown
                || !object.value(QStringLiteral("role")).isString()
                || !object.value(QStringLiteral("stable")).isBool()
                || object.value(QStringLiteral("role")).toString() != roleName(expected)
                || object.value(QStringLiteral("stable")).toBool()
                       != isBindingRole(expected)) {
                return fail(QStringLiteral("A fingerprint component has an invalid role."));
            }
            role = expected;
        }

        const QString normalized = normalizeValue(name, rawValue, policyVersion);
        if (!isUsableValue(name, normalized, policyVersion)) {
            return fail(QStringLiteral("A fingerprint component contains an unusable value."));
        }

        names.insert(name);
        components.append({name, normalized, role});
    }
    return true;
}

QString HardwareFingerprint::prettyPrint() const {
    if (!isSufficient()) {
        return QStringLiteral("Fingerprint unavailable: ") + m_error;
    }
    return QStringLiteral("Fingerprint policy %1, hash: %2")
        .arg(m_policyVersion)
        .arg(m_fingerprintHash);
}

QString HardwareFingerprint::readBoardSerial() {
    QFile file(QStringLiteral("/sys/class/dmi/id/board_serial"));
    return file.open(QIODevice::ReadOnly)
               ? QString::fromUtf8(file.readAll()).trimmed()
               : QString();
}

QString HardwareFingerprint::readBiosVersion() {
    QFile file(QStringLiteral("/sys/class/dmi/id/bios_version"));
    return file.open(QIODevice::ReadOnly)
               ? QString::fromUtf8(file.readAll()).trimmed()
               : QString();
}

QString HardwareFingerprint::readCpuModel() {
    QFile file(QStringLiteral("/proc/cpuinfo"));
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    static const QRegularExpression modelName(
        QStringLiteral("model name\\s*:\\s*(.+)"));
    const QRegularExpressionMatch match = modelName.match(
        QString::fromUtf8(file.readAll()));
    return match.hasMatch() ? match.captured(1).trimmed() : QString();
}

QString HardwareFingerprint::readSystemUuid() {
    QFile file(QStringLiteral("/sys/class/dmi/id/product_uuid"));
    return file.open(QIODevice::ReadOnly)
               ? QString::fromUtf8(file.readAll()).trimmed()
               : QString();
}

QString HardwareFingerprint::rootDiskSerialFromLsblkJson(
    const QByteArray& json,
    const QString& rootSource) {
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return {};
    }

    QList<DiskCandidate> candidates;
    const QJsonArray devices = document.object()
                                   .value(QStringLiteral("blockdevices"))
                                   .toArray();
    for (const QJsonValue& device : devices) {
        if (device.isObject()) {
            collectRootDiskCandidates(device.toObject(), rootSource,
                                      {}, candidates);
        }
    }

    QStringList serials;
    for (const DiskCandidate& candidate : candidates) {
        const QString normalized = normalizeValue(QStringLiteral("disk_serial"),
                                                  candidate.serial,
                                                  HardenedPolicyVersion);
        if (isUsableValue(QStringLiteral("disk_serial"), normalized,
                          HardenedPolicyVersion)
            && !serials.contains(normalized)) {
            serials.append(normalized);
        }
    }
    // Device names can change as Linux enumerates disks. Sort the identity
    // values themselves so multi-disk root storage remains deterministic.
    serials.sort();
    return serials.join(QLatin1Char('|'));
}

QString HardwareFingerprint::readRootDiskSerial() {
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("LC_ALL"), QStringLiteral("C"));

    QProcess findMount;
    findMount.setProcessEnvironment(environment);
    findMount.start(QStringLiteral("findmnt"),
                    {QStringLiteral("--noheadings"),
                     QStringLiteral("--output"), QStringLiteral("SOURCE"),
                     QStringLiteral("--target"), QStringLiteral("/")});
    QString rootSource;
    if (findMount.waitForFinished(2000)
        && findMount.exitStatus() == QProcess::NormalExit
        && findMount.exitCode() == 0) {
        rootSource = QString::fromUtf8(findMount.readAllStandardOutput()).trimmed();
        // findmnt can append a Btrfs subvolume in brackets. lsblk identifies
        // the backing block device without that suffix.
        const qsizetype subvolume = rootSource.indexOf(QLatin1Char('['));
        if (subvolume >= 0) {
            rootSource.truncate(subvolume);
        }
    } else if (findMount.state() != QProcess::NotRunning) {
        findMount.kill();
        findMount.waitForFinished();
    }

    QProcess process;
    process.setProcessEnvironment(environment);
    process.start(QStringLiteral("lsblk"),
                  {QStringLiteral("--json"),
                   QStringLiteral("--paths"),
                   QStringLiteral("--output"),
                   QStringLiteral("NAME,TYPE,SERIAL,MOUNTPOINT")});
    if (!process.waitForFinished(2000)) {
        process.kill();
        process.waitForFinished();
        return {};
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return {};
    }
    return rootDiskSerialFromLsblkJson(process.readAllStandardOutput(),
                                       rootSource);
}

QString HardwareFingerprint::readLegacyPrimaryDiskSerial() {
    QProcess process;
    process.start(QStringLiteral("lsblk"),
                  {QStringLiteral("-dno"), QStringLiteral("SERIAL,TYPE")});
    if (!process.waitForFinished(2000)) {
        process.kill();
        process.waitForFinished();
        return {};
    }

    const QStringList lines = QString::fromUtf8(process.readAllStandardOutput())
                                  .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString& line : lines) {
        QString candidate = line.trimmed();
        if (!candidate.endsWith(QStringLiteral(" disk"))) {
            continue;
        }
        candidate.chop(5);
        if (!candidate.trimmed().isEmpty()) {
            return candidate.trimmed();
        }
    }
    return {};
}

QString HardwareFingerprint::readMacAddresses() {
    QStringList macAddresses;
    for (const QNetworkInterface& interface : QNetworkInterface::allInterfaces()) {
        if (!(interface.flags() & QNetworkInterface::IsUp)
            || (interface.flags() & QNetworkInterface::IsLoopBack)) {
            continue;
        }
        const QString address = interface.hardwareAddress().trimmed().toLower();
        if (!address.isEmpty() && !macAddresses.contains(address)) {
            macAddresses.append(address);
        }
    }
    macAddresses.sort();
    return macAddresses.join(QLatin1Char(','));
}

QString HardwareFingerprint::readMachineId() {
    QFile file(QStringLiteral("/etc/machine-id"));
    return file.open(QIODevice::ReadOnly)
               ? QString::fromUtf8(file.readAll()).trimmed()
               : QString();
}

QString HardwareFingerprint::readOsInfo() {
    return QSysInfo::prettyProductName() + QLatin1Char(';')
           + QSysInfo::currentCpuArchitecture();
}

} // namespace licensing
