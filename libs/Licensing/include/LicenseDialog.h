#pragma once

#include "License.h"

#include <QDialog>

class QLabel;
class QPlainTextEdit;
class QProcess;
class QPushButton;

namespace licensing {

class LicenseManager;

class LicenseDialog : public QDialog {
    Q_OBJECT

public:
    explicit LicenseDialog(LicenseManager& manager, QWidget* parent = nullptr);

    bool isActivated() const;
    License activatedLicense() const;

private slots:
    void copyFingerprint();
    void initializeHardwareIdentity();
    void activateLicense();

private:
    void refreshFingerprintUi();
    QString bundledHardwareHelperPath() const;

    LicenseManager& m_manager;
    QLabel* m_fingerprintHash = nullptr;
    QPushButton* m_copyFingerprintButton = nullptr;
    QPushButton* m_initializeHardwareButton = nullptr;
    QPlainTextEdit* m_licenseInput = nullptr;
    QPushButton* m_activateButton = nullptr;
    QProcess* m_hardwareSetupProcess = nullptr;
    bool m_activated = false;
    License m_license;
};

} // namespace licensing
