#pragma once

#include <QDialog>

namespace licensing {

class LicenseManager;

class LicenseInfoDialog : public QDialog {
    Q_OBJECT

public:
    explicit LicenseInfoDialog(const LicenseManager& manager, QWidget* parent = nullptr);
};

} // namespace licensing
