#include "MainWindow.h"

#include <LicenseDialog.h>
#include <LicenseManager.h>

#include <QApplication>
#include <QMessageBox>

#include <cstdlib>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("SGI"));
    QApplication::setApplicationName(QStringLiteral("FaceDetectionViewer"));
    QApplication::setApplicationDisplayName(QStringLiteral("License"));

    licensing::LicenseManager licenseManager;
    licensing::License license;
    licensing::ValidationError error =
        licenseManager.validateStoredLicense(license);

    if (error != licensing::ValidationError::None) {
        licensing::LicenseDialog activationDialog(licenseManager);
        if (activationDialog.exec() != QDialog::Accepted
            || !activationDialog.isActivated()) {
            return EXIT_SUCCESS;
        }

        // Validate the persisted value again before creating protected UI.
        error = licenseManager.validateStoredLicense(license);
        if (error != licensing::ValidationError::None) {
            QMessageBox::critical(
                nullptr,
                QObject::tr("License validation failed"),
                licenseManager.errorToString(error));
            return EXIT_FAILURE;
        }
    }

    MainWindow mainWindow(license, licenseManager);
    mainWindow.show();
    return application.exec();
}
