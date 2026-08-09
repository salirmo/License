# License

This project contains a reusable Qt 6 licensing library under `libs/Licensing`
and a small application under `app` that demonstrates how to consume it.

At startup, the application validates the saved license's RSA-SHA256 signature,
product name, validity dates, and hardware fingerprint. If validation fails, it
opens the activation dialog. The main window is only constructed after a stored
or newly entered license validates successfully. Closing the activation dialog
therefore exits the application without exposing the main window.

## Hardware fingerprint policy

New fingerprint requests use explicit **policy version 2**. The policy separates
identifiers by what they are allowed to prove:

| Component | Linux source | Role | Affects machine validity |
| --- | --- | --- | --- |
| `system_uuid` | `/sys/class/dmi/id/product_uuid` | Strong | Yes |
| `board_serial` | `/sys/class/dmi/id/board_serial` | Strong | Yes |
| `disk_serial` | Physical disk(s) backing the `/` filesystem | Secondary | Yes |
| `machine_id` | `/etc/machine-id` | Secondary | Yes |
| `cpu_model` | CPU model text from `/proc/cpuinfo` | Informational | No |
| `bios_version` | `/sys/class/dmi/id/bios_version` | Informational | No |
| `mac` | Active, non-loopback MAC addresses | Informational | No |
| `os` | OS display name and CPU architecture | Informational | No |

Strong and secondary values are binding identifiers. Informational values remain
signed in license metadata for diagnostics, but they do not affect the hash,
count as matches or mismatches, or affect validity. A CPU model, BIOS version,
MAC address, or OS value can never independently prove that this is the licensed
machine.

Policy 2 refuses to create or accept a secure fingerprint unless it contains:

- At least one usable strong identifier; and
- At least two total usable binding identifiers.

Empty values and common firmware placeholders such as `Unknown`, `Default
String`, all-zero/all-`f` values, and `To Be Filled By O.E.M.` are discarded and
cannot strengthen a match. Binding identifiers are trimmed, case-normalized, and
format-normalized before hashing and comparison. UUID and machine-ID formats are
validated strictly.

### Exact and tolerant matching

The policy-2 fingerprint hash is built only from normalized strong and secondary
components. Each `name:value` pair is SHA-256 hashed, those digests are sorted,
joined, and SHA-256 hashed again.

Validation first checks the signed component schema, minimum identifier count,
and that the signed hash really corresponds to the signed components. It then
compares the current fingerprint:

1. An exact fingerprint hash match is valid.
2. Otherwise, individual signed binding components are compared by name and
   normalized value.
3. At least one **strong** identifier must match.
4. At most one signed binding component may be changed or missing.
5. Components newly collected by a newer client are ignored when validating an
   older signed reference.

The one-component tolerance permits a normal disk replacement or Linux reinstall
while a strong physical identifier still matches. Secondary or informational
values alone can never validate a different machine.

| Change | Policy-2 result |
| --- | --- |
| No hardware change | Valid |
| MAC/network change | Valid; informational only |
| BIOS update | Valid; informational only |
| CPU replacement or CPU-model change | Valid; informational only |
| Disk replacement | Valid as one secondary mismatch when a strong ID matches |
| Linux reinstall changing `/etc/machine-id` | Valid as one secondary mismatch when a strong ID matches |
| Motherboard replacement | Normally invalid because both strong identifiers change |
| Any two binding identifiers change or disappear | Invalid |
| Only secondary identifiers match | Invalid because no strong identifier matches |
| Different physical machine | Invalid in normal hardware configurations |

“Valid” in this table covers the hardware decision only. Format, product,
signature, issue-date, and expiration checks must also pass.

### Deterministic root-disk identity

Policy 2 no longer selects the first disk returned by `lsblk`. It parses
`lsblk --json --paths --output NAME,TYPE,SERIAL,MOUNTPOINT`, finds the device
mounted at `/`, walks its tree to the physical disk ancestor, and uses only that
disk serial. If multiple physical disks back the root filesystem, their
normalized serials are sorted and combined deterministically as one secondary
component. A missing or default serial is omitted safely.

### Fingerprint policy compatibility

- A signed fingerprint containing `policy_version: 2` uses the hardened rules
  above.
- A license with no fingerprint policy field is interpreted as legacy policy 1.
- Policy 1 reconstructs the original component names (`mb_uuid`, `bios_serial`,
  `machine_guid`, and `cpu_id`), original first-disk behavior, original hash, and
  original one-mismatch matching rule. This preserves existing signatures and
  already-issued licenses.
- The updated generator issues only policy-2 licenses. It rejects old, empty,
  insufficient, inconsistent, or default-filled fingerprint requests.
- Unsupported future policy versions are rejected explicitly rather than being
  interpreted using the wrong rules.

Legacy policy 1 remains less secure because its historical matching rule allows
any old `stable: true` component to provide the required match. It is retained
only for existing-license compatibility; reissuing licenses under policy 2 is
recommended.

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

Run the automated policy and compatibility tests with:

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
cd build
ctest --output-on-failure
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
