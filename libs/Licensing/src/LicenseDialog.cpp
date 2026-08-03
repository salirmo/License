#include "LicenseDialog.h"

#include "HardwareFingerprint.h"
#include "LicenseManager.h"

#include <QClipboard>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
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

    const HardwareFingerprint fingerprint;
    m_fingerprintHash = new QLabel(fingerprint.fingerprintHash(), fingerprintGroup);
    m_fingerprintHash->setWordWrap(true);
    m_fingerprintHash->setTextInteractionFlags(Qt::TextSelectableByMouse);
    fingerprintLayout->addWidget(new QLabel(tr("Fingerprint hash:"), fingerprintGroup));
    fingerprintLayout->addWidget(m_fingerprintHash);

    auto* fingerprintButtonRow = new QHBoxLayout;
    auto* copyButton = new QPushButton(tr("Copy fingerprint code"), fingerprintGroup);
    fingerprintButtonRow->addWidget(copyButton);
    fingerprintButtonRow->addStretch();
    fingerprintLayout->addLayout(fingerprintButtonRow);
    rootLayout->addWidget(fingerprintGroup);

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

    connect(copyButton, &QPushButton::clicked,
            this, &LicenseDialog::copyFingerprint);
    connect(m_activateButton, &QPushButton::clicked,
            this, &LicenseDialog::activateLicense);
}

bool LicenseDialog::isActivated() const {
    return m_activated;
}

License LicenseDialog::activatedLicense() const {
    return m_license;
}

void LicenseDialog::copyFingerprint() {
    const HardwareFingerprint fingerprint;
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
