#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>

namespace licensing {

class HardwareFingerprint {
public:
    struct Component {
        QString name;
        QString value;
        bool stable = false;
    };

    HardwareFingerprint();

    void refresh();
    QString fingerprintHash() const;
    QList<Component> components() const;
    QJsonObject toJson() const;
    bool tolerantMatch(const QList<Component>& reference, int tolerance) const;
    QString prettyPrint() const;

private:
    void addComponent(const QString& name, const QString& value, bool stable);
    QString readMotherboardUuid();
    QString readBiosSerial();
    QString readCpuId();
    QString readSystemUuid();
    QString readPrimaryDiskSerial();
    QString readMacAddresses();
    QString readMachineGuid();
    QString readOsInfo();

    QList<Component> m_components;
    QString m_fingerprintHash;
};

} // namespace licensing
