#include "HardwareFingerprint.h"

#include "CryptoManager.h"

#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QProcess>
#include <QRegularExpression>
#include <QStringList>
#include <QSysInfo>

namespace licensing {

HardwareFingerprint::HardwareFingerprint() {
    refresh();
}

void HardwareFingerprint::addComponent(const QString& name,
                                       const QString& value,
                                       bool stable) {
    const QString normalizedValue = value.trimmed();
    if (!normalizedValue.isEmpty()) {
        m_components.append({name, normalizedValue, stable});
    }
}

void HardwareFingerprint::refresh() {
    m_components.clear();
    m_fingerprintHash.clear();

    addComponent(QStringLiteral("mb_uuid"), readMotherboardUuid(), true);
    addComponent(QStringLiteral("bios_serial"), readBiosSerial(), true);
    addComponent(QStringLiteral("system_uuid"), readSystemUuid(), true);
    addComponent(QStringLiteral("machine_guid"), readMachineGuid(), true);
    addComponent(QStringLiteral("cpu_id"), readCpuId(), true);
    addComponent(QStringLiteral("disk_serial"), readPrimaryDiskSerial(), true);
    addComponent(QStringLiteral("mac"), readMacAddresses(), false);
    addComponent(QStringLiteral("os"), readOsInfo(), false);

    QStringList stableHashes;
    for (const Component& component : m_components) {
        if (component.stable) {
            const QByteArray value = (component.name + QLatin1Char(':') + component.value).toUtf8();
            stableHashes.append(QString::fromLatin1(CryptoManager::sha256(value).toHex()));
        }
    }
    stableHashes.sort();
    m_fingerprintHash = QString::fromLatin1(
        CryptoManager::sha256(stableHashes.join(QLatin1Char('|')).toUtf8()).toHex());
}

QString HardwareFingerprint::fingerprintHash() const {
    return m_fingerprintHash;
}

QList<HardwareFingerprint::Component> HardwareFingerprint::components() const {
    return m_components;
}

QJsonObject HardwareFingerprint::toJson() const {
    QJsonArray componentsJson;
    for (const Component& component : m_components) {
        QJsonObject object;
        object.insert(QStringLiteral("name"), component.name);
        object.insert(QStringLiteral("value"), component.value);
        object.insert(QStringLiteral("stable"), component.stable);
        componentsJson.append(object);
    }

    QJsonObject result;
    result.insert(QStringLiteral("hash"), m_fingerprintHash);
    result.insert(QStringLiteral("components"), componentsJson);
    return result;
}

bool HardwareFingerprint::tolerantMatch(const QList<Component>& reference,
                                        int tolerance) const {
    QHash<QString, QString> currentComponents;
    for (const Component& component : m_components) {
        if (component.stable) {
            currentComponents.insert(component.name, component.value);
        }
    }

    int matches = 0;
    int mismatches = 0;
    for (const Component& component : reference) {
        if (!component.stable) {
            continue;
        }

        const auto current = currentComponents.constFind(component.name);
        if (current != currentComponents.cend() && current.value() == component.value) {
            ++matches;
        } else {
            ++mismatches;
        }
    }

    return matches > 0 && mismatches <= tolerance;
}

QString HardwareFingerprint::prettyPrint() const {
    return QStringLiteral("Fingerprint Hash: ") + m_fingerprintHash;
}

QString HardwareFingerprint::readMotherboardUuid() {
    QFile file(QStringLiteral("/sys/class/dmi/id/board_serial"));
    return file.open(QIODevice::ReadOnly) ? QString::fromUtf8(file.readAll()).trimmed()
                                          : QString();
}

QString HardwareFingerprint::readBiosSerial() {
    QFile file(QStringLiteral("/sys/class/dmi/id/bios_version"));
    return file.open(QIODevice::ReadOnly) ? QString::fromUtf8(file.readAll()).trimmed()
                                          : QString();
}

QString HardwareFingerprint::readCpuId() {
    QFile file(QStringLiteral("/proc/cpuinfo"));
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    static const QRegularExpression modelName(
        QStringLiteral("model name\\s*:\\s*(.+)"));
    const QRegularExpressionMatch match = modelName.match(QString::fromUtf8(file.readAll()));
    return match.hasMatch() ? match.captured(1).trimmed() : QString();
}

QString HardwareFingerprint::readSystemUuid() {
    QFile file(QStringLiteral("/sys/class/dmi/id/product_uuid"));
    return file.open(QIODevice::ReadOnly) ? QString::fromUtf8(file.readAll()).trimmed()
                                          : QString();
}

QString HardwareFingerprint::readPrimaryDiskSerial() {
    QProcess process;
    process.start(QStringLiteral("lsblk"),
                  {QStringLiteral("-dno"), QStringLiteral("SERIAL,TYPE")});
    if (!process.waitForFinished(2000)) {
        process.kill();
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
        if (!address.isEmpty()) {
            macAddresses.append(address);
        }
    }
    macAddresses.sort();
    return macAddresses.join(QLatin1Char(','));
}

QString HardwareFingerprint::readMachineGuid() {
    QFile file(QStringLiteral("/etc/machine-id"));
    return file.open(QIODevice::ReadOnly) ? QString::fromUtf8(file.readAll()).trimmed()
                                          : QString();
}

QString HardwareFingerprint::readOsInfo() {
    return QSysInfo::prettyProductName() + QLatin1Char(';')
           + QSysInfo::currentCpuArchitecture();
}

} // namespace licensing
