cmake_minimum_required(VERSION 3.16)

project(License VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
find_package(OpenSSL REQUIRED)

include(CTest)
include(GNUInstallDirs)

add_subdirectory(libs/Licensing)
add_subdirectory(app)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(helper)
    # Building the application target from Qt Creator also builds the bundled
    # helper used by the activation dialog.
    add_dependencies(License sgi-license-hardware-identity)
endif()

install(FILES HARDWARE_IDENTITY_HELPER.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

if(BUILD_TESTING)
    find_package(Qt6 REQUIRED COMPONENTS Test)
    add_subdirectory(tests)
endif()
