add_library(Licensing STATIC)
add_library(Licensing::Licensing ALIAS Licensing)

target_sources(Licensing
    PRIVATE
        src/CryptoManager.cpp
        src/HardwareFingerprint.cpp
        src/License.cpp
        src/LicenseDialog.cpp
        src/LicenseInfoDialog.cpp
        src/LicenseManager.cpp
        src/LicenseValidator.cpp
        src/PlatformIdentity.cpp
        src/PlatformIdentityCore.cpp
        src/PlatformIdentityCore.h
        include/CryptoManager.h
        include/HardwareFingerprint.h
        include/License.h
        include/LicenseDialog.h
        include/LicenseInfoDialog.h
        include/LicenseManager.h
        include/LicenseValidator.h
        include/PlatformIdentity.h
        include/PubKey.h
)

target_include_directories(Licensing
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(Licensing PUBLIC cxx_std_17)

target_link_libraries(Licensing
    PUBLIC
        Qt6::Widgets
        Qt6::Network
    PRIVATE
        OpenSSL::Crypto
)
