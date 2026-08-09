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

add_executable(EntitlementTests
    EntitlementTests.cpp
)

target_link_libraries(EntitlementTests
    PRIVATE
        Licensing::Licensing
        Qt6::Test
        OpenSSL::Crypto
)

add_test(NAME EntitlementTests COMMAND EntitlementTests)
