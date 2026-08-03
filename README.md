# License

This project contains a reusable Qt 6 licensing library under `libs/Licensing`
and a small application under `app` that demonstrates how to consume it.

At startup, the application validates the saved license's RSA-SHA256 signature,
product name, validity dates, and hardware fingerprint. If validation fails, it
opens the activation dialog. The main window is only constructed after a stored
or newly entered license validates successfully. Closing the activation dialog
therefore exits the application without exposing the main window.

## Build

Requirements:

- CMake 3.16 or newer
- Qt 6 (`Widgets` and `Network`)
- OpenSSL development files

```bash
cmake -S . -B build
cmake --build build
./build/app/License
```

## Configure your product

Edit `libs/Licensing/include/PubKey.h` before shipping:

- Replace the public key with the public half of your signing key.

The fixed product and `QSettings` identifiers for this application are kept in
`libs/Licensing/src/LicenseManager.cpp`.

The private signing key must never be included in this repository or in the
application. The activation dialog copies a Base64-encoded hardware fingerprint
request. Your separate license-issuing tool should use that request to create the
signed `acme-license-1` key that the user pastes into the dialog.

## Set up licensing in another Qt application

### 1. Copy the library

Copy the complete `libs/Licensing` directory into the other application's
`libs` directory. Keep its `include`, `src`, and `CMakeLists.txt` files together.

### 2. Link the library

Add the subdirectory and link the namespaced target:

```cmake
find_package(Qt6 REQUIRED COMPONENTS Widgets Network)
find_package(OpenSSL REQUIRED)
add_subdirectory(libs/Licensing)
target_link_libraries(YourApp PRIVATE Licensing::Licensing)
```

### 3. Configure the signing key

The public key in `libs/Licensing/include/PubKey.h` must correspond to the
private key loaded by `LicenseGenerator`.

- Keep the existing public key when multiple applications use the same signing
  key pair.
- Replace it when the new application uses a different private key.
- Never copy or embed the private key in a client application.

### 4. Configure the product and application identity

Update the constants in `libs/Licensing/src/LicenseManager.cpp`:

```cpp
const QString kProductName = QStringLiteral("MyApp");
const QString kOrganizationName = QStringLiteral("SGI");
const QString kApplicationName = QStringLiteral("FaceDetectionViewer");
const QString kSettingsKey = QStringLiteral("license_key");
```

The generator's product must exactly match `kProductName`. The generator
currently sets it in `LicenseGenerator.cpp`:

```cpp
lic.product = "MyApp";
```

Use a different product name in both places when licenses for one application
must not activate another application. Give each application a distinct
`kApplicationName` so its saved license uses a separate `QSettings` location.

### 5. Validate before creating the main window

Perform startup validation in `main.cpp`, before constructing protected UI:

```cpp
#include <LicenseDialog.h>
#include <LicenseManager.h>

#include <QApplication>
#include <QMessageBox>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);

    licensing::LicenseManager licenseManager;
    licensing::License license;
    auto error = licenseManager.validateStoredLicense(license);

    if (error != licensing::ValidationError::None) {
        licensing::LicenseDialog activationDialog(licenseManager);
        if (activationDialog.exec() != QDialog::Accepted
            || !activationDialog.isActivated()) {
            return 0;
        }

        // Verify the persisted key again before constructing protected UI.
        error = licenseManager.validateStoredLicense(license);
        if (error != licensing::ValidationError::None) {
            QMessageBox::critical(nullptr,
                                  QObject::tr("License validation failed"),
                                  licenseManager.errorToString(error));
            return 1;
        }
    }

    MainWindow mainWindow(license, licenseManager);
    mainWindow.show();
    return application.exec();
}
```

The validation gate belongs in `main.cpp`, not in `MainWindow`. This ensures
that the main window is neither constructed nor shown before activation. Passing
`LicenseManager` into `MainWindow` is only necessary when the window needs to
open `LicenseInfoDialog` or perform another license operation.

The complete working startup example is available in `app/src/main.cpp`.
