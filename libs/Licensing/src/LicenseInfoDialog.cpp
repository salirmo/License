#include "LicenseInfoDialog.h"

#include "License.h"
#include "LicenseManager.h"

#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace licensing {
namespace {

QLineEdit* readOnlyField(QWidget* parent) {
    auto* field = new QLineEdit(parent);
    field->setReadOnly(true);
    return field;
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
    } else {
        statusLabel->setText(tr("License is invalid: %1")
                                 .arg(manager.errorToString(error)));
        statusLabel->setStyleSheet(
            QStringLiteral("color: #b42318; font-size: 14px; font-weight: bold;"));
        for (QLineEdit* field : {productField, ownerField, idField, issueField,
                                 expiryField, fingerprintField}) {
            field->setText(tr("N/A"));
        }
    }
}

} // namespace licensing
