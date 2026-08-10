# Linux hardware-identity helper deployment

Fingerprint policy 4 binds new licenses to validated DMI/SMBIOS platform
identity. A normal desktop process reads `/sys/class/dmi/id` directly when the
files are world-readable. On systems that restrict those files, the application
uses a root-created snapshot instead of requesting privileges at runtime.

The helper is a short-lived systemd oneshot service. It is not a daemon, does
not use the network, and does not grant the Qt application any additional
privileges.

## Build and install

Configure with the final installation prefix so the generated service unit has
the correct absolute helper path. A normal system installation is:

```bash
cmake \
  -S . -B build-release \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr

cmake --build build-release
sudo cmake --install build-release
sudo systemctl daemon-reload
sudo systemctl enable --now sgi-license-hardware-identity.service
```

The administrative commands are installation-time actions. The main
application itself must always run as an ordinary user.

## Installed resources

- Helper: `${libexecdir}/sgi-license-hardware-identity`
- Unit: `/usr/lib/systemd/system/sgi-license-hardware-identity.service` for the
  documented `/usr` prefix
- Snapshot: `/var/lib/sgi-license/platform-identity.json`

The service uses `StateDirectory=sgi-license`, runs once as root during boot,
and atomically publishes the snapshot with a same-directory temporary file,
`fsync`, and `rename`. The directory is mode 0755 and the file is mode 0644,
both root-owned and not writable by group or other users. The helper has no Qt
or other application runtime dependency. Its capability set is restricted to
`CAP_DAC_READ_SEARCH`, which is needed on systems that expose mode-0400 DMI
files with remapped ownership.

The snapshot contains:

```json
{
  "format": "sgi-platform-identity-1",
  "version": 1,
  "boot_id": "<current /proc/sys/kernel/random/boot_id>",
  "platform": {
    "product_uuid": "<optional validated UUID>",
    "product_serial": "<optional validated serial>",
    "board_serial": "<optional validated serial>"
  }
}
```

Invalid/default DMI values are omitted. The library accepts the file only when
the file and parent directory are root-owned and not group/other-writable, the
format is valid, and its boot ID equals the current boot ID. A stale snapshot
copied with a disk image is never used.

## Operations

Inspect the service and snapshot with:

```bash
systemctl status sgi-license-hardware-identity.service
journalctl -u sgi-license-hardware-identity.service
stat /var/lib/sgi-license /var/lib/sgi-license/platform-identity.json
```

After changing the helper or service unit, reinstall and restart it:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sgi-license-hardware-identity.service
```

If a policy-4 license contains signed platform identity but the current system
cannot obtain comparable platform identity, validation fails closed with
`PlatformIdentityUnavailable`. It does not downgrade to disk, MAC, or derived
machine-ID matching.

## Troubleshooting fingerprint collection

If the activation dialog reports:

```text
Secure fingerprint unavailable: Trusted platform identity is unavailable.
Install or refresh the systemd hardware-identity snapshot before activation.
```

the normal application could not read any trustworthy DMI platform group and
there is no valid current-boot snapshot. Check the three sources without
printing their identifying values:

```bash
for path in \
  /sys/class/dmi/id/product_uuid \
  /sys/class/dmi/id/product_serial \
  /sys/class/dmi/id/board_serial
do
  stat -c '%n mode=%a owner=%U:%G' "$path"
  test -r "$path" && echo readable || echo restricted
done
```

For a development build, the helper can create the snapshot immediately from
the activation dialog. Click **Initialize hardware identity** and approve the
system authorization prompt. CMake makes the `License` application target
depend on the bundled helper, so building the application target in Qt Creator
also builds the helper automatically. The main application remains
unprivileged.

The equivalent terminal command below is available for headless development
or troubleshooting. This is a one-time administrative operation, not how the
Qt application is launched:

```bash
sudo ./build-release/helper/sgi-license-hardware-identity
```

Restart the client after that command. The fingerprint copy button should be
enabled. Because the snapshot is intentionally tied to the Linux boot ID, this
manual command must be repeated after a reboot unless the systemd unit is
installed and enabled.

For the permanent solution, use the installation commands in **Build and
install**, then verify:

```bash
systemctl is-enabled sgi-license-hardware-identity.service
systemctl is-active sgi-license-hardware-identity.service
stat /var/lib/sgi-license/platform-identity.json
```

If the service fails, inspect it with:

```bash
journalctl -u sgi-license-hardware-identity.service -b --no-pager
```
