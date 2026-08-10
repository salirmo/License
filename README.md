# License

This project contains a reusable Qt 6 licensing library under `libs/Licensing`
and a small application under `app` that demonstrates how to consume it.

At startup, the application validates the saved license's RSA-SHA256 signature,
product name, validity dates, hardware fingerprint, and signed entitlement
schema. If validation fails, it opens the activation dialog. The main window is
only constructed after a stored or newly entered license validates
successfully. Closing the activation dialog therefore exits the application
without exposing the main window or entitlement data.

## Current hardware fingerprint policy 4

New fingerprint requests and newly issued licenses use **policy version 4**.
The policy identifies the physical platform first, so replacing the root disk,
reinstalling Linux, or doing both does not invalidate a license while the same
motherboard/system identity remains.

| Component | Linux source | Policy-4 role | Enters hash/matching |
| --- | --- | --- | --- |
| `product_uuid` | `/sys/class/dmi/id/product_uuid` | Platform (preferred) | Yes |
| `product_serial` | `/sys/class/dmi/id/product_serial` | Platform | Yes |
| `board_serial` | `/sys/class/dmi/id/board_serial` | Platform | Yes |
| `permanent_mac` | rtnetlink `IFLA_PERM_ADDRESS` on physical interfaces | Secondary | Yes |
| `derived_machine_id` | Application-specific HMAC derivation of `/etc/machine-id` | Secondary | Yes |
| `disk_serial` | Physical disk(s) backing `/` | Secondary | Yes |
| `cpu_model` | `/proc/cpuinfo` | Informational | No |
| `bios_version` | `/sys/class/dmi/id/bios_version` | Informational | No |
| `os` | Qt OS description and architecture | Informational | No |

The three DMI values form one correlated **platform evidence group**. They are
not three independent votes. A matching valid `product_uuid` confirms the
platform. When product UUID is unavailable, both `product_serial` and
`board_serial` must be present and match to confirm the platform. Malformed
UUIDs, empty/default/all-zero/all-`f` serials, `unknown`, `default string`, and
other firmware placeholders are discarded.

Only platform and secondary components enter the deterministic SHA-256
fingerprint hash. Exact hash equality remains the fast path. When the hash
changes, component-aware policy-4 matching is authoritative:

1. A matching signed/current `product_uuid` confirms the platform, regardless
   of secondary changes.
2. Without a comparable UUID, an exact signed/current product-serial and
   board-serial pair confirms the platform.
3. A comparable but different platform identity rejects the license even when
   the old disk and Linux installation still match.
4. If a trustworthy platform group was signed but is now unavailable, the
   validator returns `PlatformIdentityUnavailable`; it never downgrades to
   secondary matching.
5. Only a license issued with no platform group may use fallback matching. It
   requires at least two independent secondary matches and allows at most one
   secondary mismatch. A single secondary match is never enough.

Policy 4 explicitly represents evidence as `Match`, `Mismatch`, or
`Unavailable`. Missing evidence is not treated as changed evidence.

The raw `/etc/machine-id` is never emitted in a policy-4 request or license. The
library validates the 128-bit machine ID and derives a stable application-
specific 256-bit value with HMAC-SHA-256. Permanent MAC collection accepts only
Linux rtnetlink `IFLA_PERM_ADDRESS`; it does not silently substitute the current
or randomized `IFLA_ADDRESS`. Loopback, software-created interfaces, malformed
addresses, multicast/broadcast addresses, and duplicates are ignored. Multiple
usable permanent addresses are normalized, sorted, and combined as one
secondary component.

### Policy-4 invalidation matrix

| Change | Result | Reason |
| --- | --- | --- |
| OS/kernel/hostname update | Valid | Not platform evidence; OS is informational and hostname is not collected |
| BIOS version update | Valid | BIOS version is informational, unless real platform IDs also change |
| CPU replacement | Valid | CPU model is informational |
| Add a non-root disk | Valid | It is not part of root-disk identity |
| Replace root SSD | Valid with matching platform | Disk is secondary |
| Fresh Linux installation | Valid with matching platform | Derived machine ID is secondary |
| Replace root SSD and reinstall Linux | Valid with matching platform | Matching platform overrides secondary changes |
| Replace network adapter/permanent MAC | Valid with matching platform | Permanent MAC is secondary |
| Move the old SSD/OS to another computer | Invalid | Comparable platform identity changed |
| Clone the disk/OS to another physical computer | Invalid | Comparable platform identity changed |
| Replace motherboard/platform | Invalid/reissue required | Primary physical identity changed |
| Signed platform later becomes unavailable | Fail closed | No fallback downgrade is allowed |
| No platform at issuance; one secondary match | Invalid/insufficient | At least two matches are required |
| No platform at issuance; two matches and at most one mismatch | Valid | Meets the explicit fallback rule |

“Valid” describes the hardware decision only. Signature, product, dates,
license schema, and entitlements must also validate.

### Privileged DMI snapshot

The Qt application always runs unprivileged. When DMI files are directly
readable it uses them directly. For systems where DMI is root-readable only,
the project installs the minimal `sgi-license-hardware-identity` systemd
oneshot helper. It runs once during boot and atomically publishes:

```text
/var/lib/sgi-license/platform-identity.json
```

The library accepts the snapshot only when its file and parent directory are
root-owned and not group/other-writable, its format/version is valid, and its
signed-in snapshot boot ID matches `/proc/sys/kernel/random/boot_id` for the
current boot. A stale snapshot copied with a disk image is rejected. See
[`HARDWARE_IDENTITY_HELPER.md`](HARDWARE_IDENTITY_HELPER.md) for installation
and operations. Development builds also expose an **Initialize hardware
identity** button when a snapshot is required. It invokes only the
automatically built helper through PolicyKit; the Qt application and Qt Creator
remain unprivileged.

## Legacy fingerprint policy 3 compatibility

Already-issued policy-3 licenses use explicit **policy version 3**. It produces a
device-specific fingerprint as a normal Linux user and never asks for root or
PolicyKit authorization. Identifiers remain separated by their role:

| Component | Linux source | Role | Affects machine validity |
| --- | --- | --- | --- |
| `system_uuid` | `/sys/class/dmi/id/product_uuid`, when already readable | Strong | Yes, when present |
| `board_serial` | `/sys/class/dmi/id/board_serial`, when already readable | Strong | Yes, when present |
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

Policy 3 refuses to create or accept a fingerprint unless it contains both
normally unprivileged device identifiers:

- The deterministic root `disk_serial`; and
- `/etc/machine-id`.

Empty values and common firmware placeholders such as `Unknown`, `Default
String`, all-zero/all-`f` values, and `To Be Filled By O.E.M.` are discarded and
cannot strengthen a match. Binding identifiers are trimmed, case-normalized, and
format-normalized before hashing and comparison. UUID and machine-ID formats are
validated strictly.

Readable DMI identifiers are collected as additional strong bindings, but they
are optional. If Linux protects them with mode `0400`, the collector simply
omits them. It does not call an authorization service, show a password dialog,
or elevate the process. CPU, BIOS, MAC, and OS values still cannot prove machine
identity.

### Exact and tolerant matching

The policy-3 fingerprint hash is built only from normalized strong and secondary
components. Each `name:value` pair is SHA-256 hashed, those digests are sorted,
joined, and SHA-256 hashed again.

Validation first checks the signed component schema, minimum identifier count,
and that the signed hash really corresponds to the signed components. It then
compares the current fingerprint:

1. An exact fingerprint hash match is valid.
2. Otherwise, individual signed binding components are compared by name and
   normalized value.
3. At least one binding identifier must match.
4. At most one signed binding component may be changed or missing.
5. Components newly collected by a newer client are ignored when validating an
   older signed reference.
6. A policy-3 DMI component that becomes unreadable is ignored rather than
   counted as a hardware change.

The required disk serial and machine ID normally differ between independent
devices, so their fingerprint hashes differ. The one-component tolerance permits
a disk replacement while `machine_id` matches, or a Linux reinstall while
`disk_serial` matches. Informational values never participate.

| Change | Policy-3 result |
| --- | --- |
| No hardware change | Valid |
| MAC/network change | Valid; informational only |
| BIOS update | Valid; informational only |
| CPU replacement or CPU-model change | Valid; informational only |
| Disk replacement | Valid when `machine_id` still matches |
| Linux reinstall changing `/etc/machine-id` | Valid when `disk_serial` still matches |
| Motherboard replacement | Invalid when two readable DMI identifiers change; otherwise may remain valid |
| Any two binding identifiers change or disappear | Invalid |
| Different physical machine | Invalid in normal hardware configurations |

“Valid” in this table covers the hardware decision only. Format, product,
signature, issue-date, and expiration checks must also pass.

### Deterministic root-disk identity

Policy 3 does not select the first disk returned by `lsblk`. It parses
`lsblk --json --paths --output NAME,TYPE,SERIAL,MOUNTPOINT`, finds the device
mounted at `/`, walks its tree to the physical disk ancestor, and uses only that
disk serial. If multiple physical disks back the root filesystem, their
normalized serials are sorted and combined deterministically as one secondary
component. A missing or default serial is omitted safely.

### Fingerprint policy compatibility

- A signed fingerprint containing `policy_version: 3` uses the unprivileged
  rules above.
- Already-issued policy-2 licenses retain their original requirement for a
  matching DMI strong identifier. Policy 3 does not reinterpret their signed
  component roles or matching rules.
- A license with no fingerprint policy field is interpreted as legacy policy 1.
- Policy 1 reconstructs the original component names (`mb_uuid`, `bios_serial`,
  `machine_guid`, and `cpu_id`), original first-disk behavior, original hash, and
  original one-mismatch matching rule. This preserves existing signatures and
  already-issued licenses.
- The updated generator issues only policy-4 licenses. It rejects old, empty,
  insufficient, inconsistent, or default-filled fingerprint requests.
- Unsupported future policy versions are rejected explicitly rather than being
  interpreted using the wrong rules.

Legacy policy 1 remains less secure because its historical matching rule allows
any old `stable: true` component to provide the required match. It is retained
only for existing-license compatibility. Reissue older licenses under policy 4
when password-free collection is required.

Policy 3 deliberately trades guaranteed motherboard detection for unprivileged
operation on Linux machines that hide all DMI serials. A deliberately cloned
installation can only be distinguished by values that were not cloned; no
offline user-space collector can promise uniqueness when every readable binding
identifier is copied or the original root disk is physically moved.

## Signed module entitlements and resource limits

New licenses use `payload.version: 2` and carry an `entitlements` object inside
the RSA-signed payload:

```json
{
  "entitlements": {
    "modules": [
      {
        "id": "face",
        "display_name": "Face",
        "camera_limit": {
          "mode": "limited",
          "value": 8
        }
      },
      {
        "id": "lpr",
        "display_name": "LPR",
        "camera_limit": {
          "mode": "unlimited"
        }
      },
      {
        "id": "parking",
        "display_name": "Parking Management",
        "camera_limit": {
          "mode": "limited",
          "value": 4
        }
      }
    ],
    "user_limit": {
      "mode": "limited",
      "value": 10
    }
  }
}
```

A module's presence in `modules` means it is enabled. There is no separate
`enabled` flag. The licensing library handles `face`, `lpr`, `parking`, and any
future ID through the same generic representation; it contains no module-name
branches.

`display_name` is optional informational text. Module identity comes only from
`id`. IDs are trimmed and lowercased, limited to 64 characters, begin with a
lowercase ASCII letter, and then contain only lowercase ASCII letters, digits,
or single underscores. Empty, invalid, and duplicate normalized IDs reject the
license. `other` is reserved for the Generator's UI grouping and is not a valid
signed module ID.

Both camera and user limits use one of these unambiguous forms:

```json
{ "mode": "limited", "value": 10 }
```

```json
{ "mode": "unlimited" }
```

Limited values must be positive integers. Unlimited values omit `value`. A
missing, zero, negative, fractional, ambiguous, or unknown-mode limit rejects
the license and never turns into unlimited access. `user_limit` means the
maximum number of configured application user accounts, not concurrent
sessions.

All entitlement data is inside the canonical payload covered by the RSA
signature. Editing a module, camera limit, or user limit in the transported JSON
causes signature validation to fail.

### Validation gate

The client intentionally keeps entitlement JSON inaccessible while validating:

```text
Decode license and parse required envelope
    -> verify RSA signature
    -> validate product and dates
    -> validate hardware fingerprint
    -> validate entitlement schema
    -> return validated License and expose entitlements
```

`License::fromJson()` retains the signed entitlement value only so
`License::canonical()` can verify the signature. It does not activate the typed
API. `LicenseValidator` activates entitlements only after every existing check
passes. A validation failure clears the output `License`, preventing previously
validated values from remaining in a reused output object.

Malformed entitlement structures return `ValidationError::EntitlementsInvalid`.
An edited but otherwise well-formed entitlement normally returns
`ValidationError::SignatureInvalid` first because its signature no longer
matches.

### Client entitlement API

Application code consumes the already-validated `licensing::License`; it never
parses raw license JSON:

```cpp
if (license.isModuleEnabled(QStringLiteral("face"))) {
    const licensing::ResourceLimit cameras =
        license.moduleCameraLimit(QStringLiteral("face"));

    if (cameras.unlimited) {
        // Permit any configured Face cameras.
    } else {
        // Enforce cameras.value as the maximum configured Face cameras.
    }
}

const licensing::ResourceLimit users = license.userLimit();
if (!users.unlimited) {
    // Enforce users.value as the maximum configured application accounts.
}

for (const licensing::LicensedModule& module : license.licensedModules()) {
    // Generic handling also works for parking, crowd_detection, or a future ID.
}
```

The complete API is:

```cpp
bool entitlementsAvailable() const;
bool isModuleEnabled(const QString& moduleId) const;
ResourceLimit moduleCameraLimit(const QString& moduleId) const;
ResourceLimit userLimit() const;
QList<LicensedModule> licensedModules() const;
```

Unknown or missing modules return disabled. Their resource limit is the
fail-closed default `{ unlimited = false, value = 0 }`; that zero does not mean
unlimited. `entitlementsAvailable()` must be checked when the application needs
to distinguish a legacy license from a schema-2 license containing zero
modules.

### Generator behavior

The sibling Generator offers predefined Face and LPR checkboxes, each with a
positive Limited camera count or Unlimited. Unchecked modules are omitted. Its
**Other Modules** section creates real dynamic IDs such as `parking` and
`crowd_detection`; `other` itself is a reserved UI label and is never stored as
an entitlement. Dynamic rows cannot duplicate `face`, `lpr`, or another row.

### License-schema compatibility

License schema and fingerprint policy are versioned independently:

- Schema 1 licenses have no `entitlements` member. They continue through their
  original RSA, product, date, and hardware validation. The API reports
  `entitlementsAvailable() == false`, enables no modules, and invents no limits.
- Schema 2 licenses require a valid signed `modules` array and `user_limit`.
  An empty array is valid and explicitly licenses no modules.
- `fingerprint.policy_version` still independently selects policy 1, 2, 3, or 4
  hardware behavior. Entitlement schema changes do not reinterpret it.
- The transport envelope remains `acme-license-1`; unsupported future payload
  schema versions are rejected explicitly.

The demo main window and License Information dialog render only the entitlement
objects returned by a successful validation. They are a read-only reference for
integrating the same API into the real host application.

## Build

Requirements:

- CMake 3.16 or newer
- Qt 6 (`Core`, `Widgets`, and `Network`)
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
