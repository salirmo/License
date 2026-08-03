#pragma once

#include <License.h>

#include <QMainWindow>

namespace licensing {
class LicenseManager;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(const licensing::License& license,
               const licensing::LicenseManager& licenseManager,
               QWidget* parent = nullptr);

private slots:
    void showLicenseInformation();

private:
    const licensing::LicenseManager& m_licenseManager;
};
