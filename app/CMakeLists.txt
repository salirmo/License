add_executable(License
    include/MainWindow.h
    src/MainWindow.cpp
    src/main.cpp
)

target_include_directories(License
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(License
    PRIVATE
        Licensing::Licensing
        Qt6::Widgets
)

set_target_properties(License PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
)

install(TARGETS License
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
