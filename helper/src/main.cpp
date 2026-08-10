#include "PlatformIdentityCore.h"

#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const licensing::platform_core::DirectIdentity identity =
        licensing::platform_core::readDirect();
    if (identity.inaccessibleDmi) {
        std::cerr
            << "One or more DMI identity files exist but cannot be read.\n";
        return EXIT_FAILURE;
    }

    const std::string bootId = licensing::platform_core::currentBootId();
    std::string error;
    if (!licensing::platform_core::writeSnapshotAtomically(
            licensing::platform_core::defaultSnapshotPath(),
            identity.values, bootId, &error)) {
        std::cerr << error << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
