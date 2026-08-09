#include "LicenseInfoDialog.h"

#include "License.h"
#include "LicenseManager.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>

namespace licensing {
namespace {

QLineEdit* readOnlyField(QWidget* parent) {
    auto* field = new QLineEdit(parent);
    field->setReadOnly(true);
    return field;
}

QString limitText(const ResourceLimit& limit) {
    return limit.unlimited ? QObject::tr("Unlimited")
                           : QString::number(limit.value);
}

QString entitlementText(const License& license) {
    if (!license.entitlementsAvailable()) {
        return QObject::tr(
            "Entitlement information is unavailable for this legacy license.");
    }

    QStringList lines;
    lines.append(QObject::tr("Modules"));
    const QList<LicensedModule> modules = license.licensedModules();
    if (modules.isEmpty()) {
        lines.append(QObject::tr("None"));
    } else {
        for (const LicensedModule& module : modules) {
            lines.append(QString());
            lines.append(module.displayName.isEmpty()
                             ? module.id
                             : module.displayName);
            lines.append(QObject::tr("Module ID: %1").arg(module.id));
            lines.append(QObject::tr("Camera Limit: %1")
                             .arg(limitText(module.cameraLimit)));
        }
    }
    lines.append(QString());
    lines.append(QObject::tr("User Limit: %1")
                     .arg(limitText(license.userLimit())));
    return lines.join(QLatin1Char('\n'));
}

} // namespace

LicenseInfoDialog::LicenseInfoDialog(const LicenseManager& manager, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("License information"));
    setMinimumWidth(500);

    auto* rootLayout = new QVBoxLayout(this);
    auto* statusLabel = new QLabel(tr("Checking license..."), this);
    statusLabel->setAlignment(Qt::AlignCenter);
    rootLayout->addWidget(statusLabel);

    auto* productField = readOnlyField(this);
    auto* ownerField = readOnlyField(this);
    auto* idField = readOnlyField(this);
    auto* issueField = readOnlyField(this);
    auto* expiryField = readOnlyField(this);
    auto* fingerprintField = readOnlyField(this);

    auto* formLayout = new QFormLayout;
    formLayout->addRow(tr("Product:"), productField);
    formLayout->addRow(tr("Licensed to:"), ownerField);
    formLayout->addRow(tr("License ID:"), idField);
    formLayout->addRow(tr("Issue date:"), issueField);
    formLayout->addRow(tr("Expiration date:"), expiryField);
    formLayout->addRow(tr("Machine fingerprint:"), fingerprintField);
    rootLayout->addLayout(formLayout);

    auto* entitlementsGroup = new QGroupBox(tr("Entitlements"), this);
    auto* entitlementsLayout = new QVBoxLayout(entitlementsGroup);
    auto* entitlementsField = new QPlainTextEdit(entitlementsGroup);
    entitlementsField->setReadOnly(true);
    entitlementsField->setMinimumHeight(180);
    entitlementsLayout->addWidget(entitlementsField);
    rootLayout->addWidget(entitlementsGroup);

    auto* closeButton = new QPushButton(tr("Close"), this);
    rootLayout->addWidget(closeButton, 0, Qt::AlignRight);
    connect(closeButton, &QPushButton::clicked,
            this, &QDialog::accept);

    License license;
    const ValidationError error = manager.validateStoredLicense(license);
    if (error == ValidationError::None) {
        statusLabel->setText(tr("License is valid"));
        statusLabel->setStyleSheet(
            QStringLiteral("color: #16833b; font-size: 14px; font-weight: bold;"));
        productField->setText(license.product);
        ownerField->setText(license.owner.isEmpty() ? tr("N/A") : license.owner);
        idField->setText(license.licenseId);
        issueField->setText(
            license.issueDate.toLocalTime().toString(QStringLiteral("yyyy-MM-dd hh:mm AP")));
        expiryField->setText(
            license.expiryDate.isValid()
                ? license.expiryDate.toLocalTime().toString(
                      QStringLiteral("yyyy-MM-dd hh:mm AP"))
                : tr("Lifetime / perpetual"));
        fingerprintField->setText(license.fingerprintHash);
        entitlementsField->setPlainText(entitlementText(license));
    } else {
        statusLabel->setText(tr("License is invalid: %1")
                                 .arg(manager.errorToString(error)));
        statusLabel->setStyleSheet(
            QStringLiteral("color: #b42318; font-size: 14px; font-weight: bold;"));
        for (QLineEdit* field : {productField, ownerField, idField, issueField,
                                 expiryField, fingerprintField}) {
            field->setText(tr("N/A"));
        }
        entitlementsField->setPlainText(tr("N/A"));
    }
}

} // namespace licensing
