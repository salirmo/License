#pragma once

#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QString>

namespace licensing {

class HardwareFingerprint {
public:
    enum class ComponentRole {
        Unknown,
        Strong,
        Secondary,
        Informational
    };

    struct Component {
        QString name;
        QString value;
        ComponentRole role = ComponentRole::Unknown;
    };

    struct MatchResult {
        bool valid = false;
        int strongMatches = 0;
        int bindingMatches = 0;
        int mismatches = 0;
    };

    static constexpr int LegacyPolicyVersion = 1;
    static constexpr int HardenedPolicyVersion = 2;
    // Policy 3 keeps weak diagnostic values out of machine matching but can
    // create a device-specific fingerprint without privileged DMI access.
    static constexpr int UnprivilegedPolicyVersion = 3;
    static constexpr int CurrentPolicyVersion = UnprivilegedPolicyVersion;
    static constexpr int HardwareChangeTolerance = 1;
    static constexpr int MinimumBindingIdentifiers = 2;

    explicit HardwareFingerprint(int policyVersion = CurrentPolicyVersion);

    // Creates a fingerprint from supplied probe values. This is useful for
    // deterministic validation and tests; values are normalized exactly as
    // values collected from the local machine are normalized.
    static HardwareFingerprint fromComponents(
        int policyVersion,
        const QList<Component>& components);

    void refresh();
    int policyVersion() const;
    bool isSufficient() const;
    QString errorString() const;
    QString fingerprintHash() const;
    QList<Component> components() const;
    QJsonObject toJson() const;
    bool tolerantMatch(const QList<Component>& reference, int tolerance) const;
    MatchResult match(const QList<Component>& reference, int tolerance) const;
    QString prettyPrint() const;

    static bool isSupportedPolicy(int policyVersion);
    static bool isBindingRole(ComponentRole role);
    static QString roleName(ComponentRole role);
    static ComponentRole componentRole(const QString& name, int policyVersion);
    static QString normalizeValue(const QString& name,
                                  const QString& value,
                                  int policyVersion);
    static bool isUsableValue(const QString& name,
                              const QString& normalizedValue,
                              int policyVersion);
    static bool hasSufficientIdentifiers(const QList<Component>& components,
                                         int policyVersion);
    static QString calculateHash(const QList<Component>& components,
                                 int policyVersion);
    static MatchResult evaluateMatch(const QList<Component>& current,
                                     const QList<Component>& reference,
                                     int policyVersion,
                                     int tolerance);
    static bool parseComponents(const QJsonArray& json,
                                int policyVersion,
                                QList<Component>& components,
                                QString* error = nullptr);

    // Selects the serial belonging to the physical disk ancestor of the block
    // device mounted at '/'. Exposed as a pure parser so disk selection can be
    // tested without depending on the host running the test.
    static QString rootDiskSerialFromLsblkJson(
        const QByteArray& json,
        const QString& rootSource = {});

private:
    struct SkipRefreshTag {};
    HardwareFingerprint(int policyVersion, SkipRefreshTag);

    void addComponent(const QString& name,
                      const QString& value,
                      ComponentRole role);
    void finalize();

    QString readBoardSerial();
    QString readBiosVersion();
    QString readCpuModel();
    QString readSystemUuid();
    QString readRootDiskSerial();
    QString readLegacyPrimaryDiskSerial();
    QString readMacAddresses();
    QString readMachineId();
    QString readOsInfo();

    int m_policyVersion = CurrentPolicyVersion;
    QList<Component> m_components;
    QString m_fingerprintHash;
    QString m_error;
};

} // namespace licensing
