#include "MainWindow.h"

#include <LicenseInfoDialog.h>
#include <LicenseManager.h>

#include <QAction>
#include <QGroupBox>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QStringList>
#include <QVBoxLayout>
#include <QWidget>

namespace {

QString limitText(const licensing::ResourceLimit& limit) {
    return limit.unlimited ? QObject::tr("Unlimited")
                           : QString::number(limit.value);
}

QString entitlementText(const licensing::License& license) {
    if (!license.entitlementsAvailable()) {
        return QObject::tr(
            "Entitlement information is unavailable for this legacy license.");
    }

    QStringList lines;
    lines.append(QObject::tr("Modules"));
    const QList<licensing::LicensedModule> modules = license.licensedModules();
    if (modules.isEmpty()) {
        lines.append(QObject::tr("None"));
    } else {
        for (const licensing::LicensedModule& module : modules) {
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

MainWindow::MainWindow(const licensing::License& license,
                       const licensing::LicenseManager& licenseManager,
                       QWidget* parent)
    : QMainWindow(parent),
      m_licenseManager(licenseManager) {
    setWindowTitle(tr("License"));
    resize(900, 560);

    auto* centralWidget = new QWidget(this);
    auto* layout = new QVBoxLayout(centralWidget);

    auto* heading = new QLabel(tr("Application main window"), centralWidget);
    heading->setAlignment(Qt::AlignCenter);
    heading->setStyleSheet(
        QStringLiteral("font-size: 26px; font-weight: 600;"));
    layout->addStretch();
    layout->addWidget(heading);

    auto* licenseSummary = new QLabel(
        tr("Activated for %1")
            .arg(license.owner.isEmpty() ? tr("licensed user") : license.owner),
        centralWidget);
    licenseSummary->setAlignment(Qt::AlignCenter);
    layout->addWidget(licenseSummary);

    auto* entitlementGroup = new QGroupBox(tr("Validated license entitlements"),
                                           centralWidget);
    auto* entitlementLayout = new QVBoxLayout(entitlementGroup);
    auto* entitlementView = new QPlainTextEdit(entitlementGroup);
    entitlementView->setReadOnly(true);
    entitlementView->setPlainText(entitlementText(license));
    entitlementLayout->addWidget(entitlementView);
    layout->addWidget(entitlementGroup);
    layout->addStretch();
    setCentralWidget(centralWidget);

    auto* fileMenu = menuBar()->addMenu(tr("&File"));
    auto* quitAction = fileMenu->addAction(tr("&Quit"));
    connect(quitAction, &QAction::triggered, this, &QWidget::close);

    auto* helpMenu = menuBar()->addMenu(tr("&Help"));
    auto* licenseAction = helpMenu->addAction(tr("&License information"));
    connect(licenseAction, &QAction::triggered,
            this, &MainWindow::showLicenseInformation);

    statusBar()->showMessage(tr("License valid"));
}

void MainWindow::showLicenseInformation() {
    licensing::LicenseInfoDialog dialog(m_licenseManager, this);
    dialog.exec();
}
