add_executable(sgi-license-hardware-identity
    src/main.cpp
    ${CMAKE_SOURCE_DIR}/libs/Licensing/src/PlatformIdentityCore.cpp
    ${CMAKE_SOURCE_DIR}/libs/Licensing/src/PlatformIdentityCore.h
)

target_include_directories(sgi-license-hardware-identity
    PRIVATE
        ${CMAKE_SOURCE_DIR}/libs/Licensing/src
)

target_compile_features(sgi-license-hardware-identity PRIVATE cxx_std_17)
set_target_properties(sgi-license-hardware-identity PROPERTIES AUTOMOC OFF)

install(TARGETS sgi-license-hardware-identity
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}
)

configure_file(
    ${CMAKE_SOURCE_DIR}/packaging/systemd/sgi-license-hardware-identity.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/sgi-license-hardware-identity.service
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/sgi-license-hardware-identity.service
    DESTINATION lib/systemd/system
)
