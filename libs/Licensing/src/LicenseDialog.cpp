#include "LicenseDialog.h"

#include "HardwareFingerprint.h"
#include "LicenseManager.h"

#include <QClipboard>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QStandardPaths>
#include <QStringList>
#include <QVBoxLayout>

namespace licensing {

LicenseDialog::LicenseDialog(LicenseManager& manager, QWidget* parent)
    : QDialog(parent),
      m_manager(manager) {
    setWindowTitle(tr("Activate application"));
    setModal(true);
    resize(620, 430);

    auto* rootLayout = new QVBoxLayout(this);

    auto* introduction = new QLabel(
        tr("A valid license is required before the application can start."), this);
    introduction->setWordWrap(true);
    rootLayout->addWidget(introduction);

    auto* fingerprintGroup = new QGroupBox(
        tr("Step 1: Copy this machine's fingerprint"), this);
    auto* fingerprintLayout = new QVBoxLayout(fingerprintGroup);

    m_fingerprintHash = new QLabel(fingerprintGroup);
    m_fingerprintHash->setWordWrap(true);
    m_fingerprintHash->setTextInteractionFlags(Qt::TextSelectableByMouse);
    fingerprintLayout->addWidget(new QLabel(tr("Fingerprint hash:"), fingerprintGroup));
    fingerprintLayout->addWidget(m_fingerprintHash);

    auto* fingerprintButtonRow = new QHBoxLayout;
    m_copyFingerprintButton = new QPushButton(
        tr("Copy fingerprint code"), fingerprintGroup);
    fingerprintButtonRow->addWidget(m_copyFingerprintButton);
#ifdef Q_OS_LINUX
    m_initializeHardwareButton = new QPushButton(
        tr("Initialize hardware identity"), fingerprintGroup);
    m_initializeHardwareButton->setToolTip(tr(
        "Runs only the bundled identity helper with system authorization. "
        "The application itself remains unprivileged."));
    fingerprintButtonRow->addWidget(m_initializeHardwareButton);
#endif
    fingerprintButtonRow->addStretch();
    fingerprintLayout->addLayout(fingerprintButtonRow);
    rootLayout->addWidget(fingerprintGroup);

    refreshFingerprintUi();

    auto* activationGroup = new QGroupBox(
        tr("Step 2: Paste the issued license key"), this);
    auto* activationLayout = new QVBoxLayout(activationGroup);
    m_licenseInput = new QPlainTextEdit(activationGroup);
    m_licenseInput->setPlaceholderText(tr("Paste the Base64 license key here..."));
    activationLayout->addWidget(m_licenseInput);

    auto* activationButtonRow = new QHBoxLayout;
    activationButtonRow->addStretch();
    m_activateButton = new QPushButton(tr("Activate"), activationGroup);
    m_activateButton->setDefault(true);
    activationButtonRow->addWidget(m_activateButton);
    activationLayout->addLayout(activationButtonRow);
    rootLayout->addWidget(activationGroup, 1);

    connect(m_copyFingerprintButton, &QPushButton::clicked,
            this, &LicenseDialog::copyFingerprint);
#ifdef Q_OS_LINUX
    connect(m_initializeHardwareButton, &QPushButton::clicked,
            this, &LicenseDialog::initializeHardwareIdentity);
#endif
    connect(m_activateButton, &QPushButton::clicked,
            this, &LicenseDialog::activateLicense);
}

bool LicenseDialog::isActivated() const {
    return m_activated;
}

License LicenseDialog::activatedLicense() const {
    return m_license;
}

void LicenseDialog::refreshFingerprintUi() {
    const HardwareFingerprint fingerprint;
    if (fingerprint.isSufficient()) {
        m_fingerprintHash->setText(fingerprint.fingerprintHash());
        m_fingerprintHash->setStyleSheet({});
        m_copyFingerprintButton->setEnabled(true);
        m_copyFingerprintButton->setToolTip({});
    } else {
        m_fingerprintHash->setText(
            tr("Secure fingerprint unavailable: %1")
                .arg(fingerprint.errorString()));
        m_fingerprintHash->setStyleSheet(QStringLiteral("color: #b42318;"));
        m_copyFingerprintButton->setEnabled(false);
        m_copyFingerprintButton->setToolTip(fingerprint.errorString());
    }

#ifdef Q_OS_LINUX
    m_initializeHardwareButton->setVisible(
        fingerprint.platformIdentitySetupRequired());
#endif
}

QString LicenseDialog::bundledHardwareHelperPath() const {
#ifdef Q_OS_LINUX
    const QString applicationDirectory =
        QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        QStringLiteral("/usr/libexec/sgi-license-hardware-identity"),
        QStringLiteral("/usr/local/libexec/sgi-license-hardware-identity"),
        QDir(applicationDirectory).absoluteFilePath(
            QStringLiteral("../helper/sgi-license-hardware-identity")),
        QDir(applicationDirectory).absoluteFilePath(
            QStringLiteral("sgi-license-hardware-identity"))
    };

    for (const QString& candidate : candidates) {
        const QFileInfo information(candidate);
        if (information.isFile() && information.isExecutable()) {
            return information.canonicalFilePath();
        }
    }
#endif
    return {};
}

void LicenseDialog::initializeHardwareIdentity() {
#ifdef Q_OS_LINUX
    if (m_hardwareSetupProcess
        && m_hardwareSetupProcess->state() != QProcess::NotRunning) {
        return;
    }

    const QString helperPath = bundledHardwareHelperPath();
    if (helperPath.isEmpty()) {
        QMessageBox::critical(
            this, tr("Hardware helper unavailable"),
            tr("The bundled hardware-identity helper was not found. Rebuild "
               "the License target in Qt Creator; it now builds the helper "
               "automatically."));
        return;
    }

    const QString authorizationTool =
        QStandardPaths::findExecutable(QStringLiteral("pkexec"));
    if (authorizationTool.isEmpty()) {
        QMessageBox::critical(
            this, tr("System authorization unavailable"),
            tr("The system authorization tool 'pkexec' is not installed. "
               "Install PolicyKit or deploy the systemd helper using the "
               "documented installation procedure."));
        return;
    }

    if (QMessageBox::question(
            this, tr("Initialize hardware identity"),
            tr("Linux restricts this computer's motherboard identity to the "
               "administrator. Run the bundled minimal helper now?\n\n"
               "Only the helper is authorized. The Qt application continues "
               "running as your normal user.\n\nHelper: %1")
                .arg(QDir::toNativeSeparators(helperPath)))
        != QMessageBox::Yes) {
        return;
    }

    m_initializeHardwareButton->setEnabled(false);
    m_initializeHardwareButton->setText(tr("Waiting for authorization..."));
    m_hardwareSetupProcess = new QProcess(this);
    QProcess* const process = m_hardwareSetupProcess;

    connect(process, &QProcess::errorOccurred, this,
            [this, process](QProcess::ProcessError processError) {
        if (processError != QProcess::FailedToStart
            || process != m_hardwareSetupProcess) {
            return;
        }
        m_hardwareSetupProcess = nullptr;
        process->deleteLater();
        m_initializeHardwareButton->setEnabled(true);
        m_initializeHardwareButton->setText(
            tr("Initialize hardware identity"));
        QMessageBox::critical(
            this, tr("Hardware identity setup failed"),
            tr("The system authorization process could not be started."));
    });

    connect(process,
            qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this,
            [this, process](int exitCode, QProcess::ExitStatus exitStatus) {
        if (process != m_hardwareSetupProcess) {
            return;
        }
        const QString diagnostic = QString::fromUtf8(
            process->readAllStandardError()).trimmed().left(1000);
        m_hardwareSetupProcess = nullptr;
        process->deleteLater();
        m_initializeHardwareButton->setEnabled(true);
        m_initializeHardwareButton->setText(
            tr("Initialize hardware identity"));

        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            QMessageBox::warning(
                this, tr("Hardware identity setup not completed"),
                diagnostic.isEmpty()
                    ? tr("Authorization was cancelled or the helper failed.")
                    : diagnostic);
            refreshFingerprintUi();
            return;
        }

        refreshFingerprintUi();
        const HardwareFingerprint refreshed;
        if (refreshed.isSufficient()) {
            QMessageBox::information(
                this, tr("Hardware identity initialized"),
                tr("The secure fingerprint is ready and can now be copied."));
        } else {
            QMessageBox::critical(
                this, tr("Hardware identity unavailable"),
                refreshed.errorString());
        }
    });

    process->start(authorizationTool, {helperPath});
#endif
}

void LicenseDialog::copyFingerprint() {
    const HardwareFingerprint fingerprint;
    if (!fingerprint.isSufficient()) {
        QMessageBox::critical(
            this,
            tr("Hardware fingerprint unavailable"),
            fingerprint.errorString());
        return;
    }

    const QByteArray json = QJsonDocument(fingerprint.toJson())
                                .toJson(QJsonDocument::Compact);
    QGuiApplication::clipboard()->setText(
        QString::fromLatin1(json.toBase64()));

    QMessageBox::information(
        this,
        tr("Fingerprint copied"),
        tr("The fingerprint code is on the clipboard. Send it to your license issuer."));
}

void LicenseDialog::activateLicense() {
    const QString licenseKey = m_licenseInput->toPlainText().trimmed();
    if (licenseKey.isEmpty()) {
        QMessageBox::warning(this, tr("License required"),
                             tr("Paste a license key before activating."));
        return;
    }

    License license;
    const ValidationError error = m_manager.validate(licenseKey, license);
    if (error != ValidationError::None) {
        QMessageBox::critical(this, tr("Activation failed"),
                              m_manager.errorToString(error));
        return;
    }

    m_manager.storeLicenseKey(licenseKey);
    m_license = license;
    m_activated = true;

    QMessageBox::information(this, tr("Activated"),
                             tr("The license was activated successfully."));
    accept();
}

} // namespace licensing
