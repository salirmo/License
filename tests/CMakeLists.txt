add_executable(LicensingTests
    HardwareFingerprintTests.cpp
)

target_link_libraries(LicensingTests
    PRIVATE
        Licensing::Licensing
        Qt6::Test
        OpenSSL::Crypto
)

add_test(NAME LicensingTests COMMAND LicensingTests)
