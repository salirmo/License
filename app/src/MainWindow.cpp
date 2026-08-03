#include "MainWindow.h"

#include <LicenseInfoDialog.h>
#include <LicenseManager.h>

#include <QAction>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

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
