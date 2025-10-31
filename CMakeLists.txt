cmake_minimum_required(VERSION 3.16)
project(QtSecureServer LANGUAGES CXX)

# C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt 6 Module (passe an, falls du z.B. kein Mqtt installiert hast)
find_package(Qt6 REQUIRED COMPONENTS
    Core
    Gui
    Widgets
    Network
    Sql
    WebSockets
    StateMachine
    Mqtt
    SerialBus
    Charts
)

# -----------------------------------------
# Quellen einsammeln
# -----------------------------------------
file(GLOB_RECURSE APP_SOURCES
    src/main.cpp
    src/ui/*.cpp
    src/http/*.cpp
    src/db/*.cpp
    src/mqtt/*.cpp
    src/modbus/*.cpp
    # falls du .cpp in common hast:
    src/common/*.cpp
)

file(GLOB_RECURSE APP_HEADERS
    src/ui/*.h
    src/http/*.h
    src/db/*.h
    src/mqtt/*.h
    src/modbus/*.h
    src/common/*.h
)

add_executable(${PROJECT_NAME}
    ${APP_SOURCES}
    ${APP_HEADERS}  # nur damit sie im Qt Creator sichtbar sind
)

# GCC/Clang (MinGW/ClangCL)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wshadow -Wpedantic)
endif()

# MSVC (Visual Studio Toolchain)
if (MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE /W4 /permissive-)
  # optional hart: /WX  (behandelt Warnungen als Fehler)
endif()

# Header-Ordner für Helper (header-only)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common
)

target_link_libraries(${PROJECT_NAME}
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    Qt6::Sql
    Qt6::WebSockets
    Qt6::StateMachine
    Qt6::Mqtt
    Qt6::SerialBus
    Qt6::Charts
)

# Automoc/UIC/RCC
set_target_properties(${PROJECT_NAME} PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    AUTORCC ON
)

# Windows GUI (keine Konsolenbox)
if (WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# -----------------------------------------
# Tools unter src/tools (wie bei dir)
# -----------------------------------------
file(GLOB TOOL_SRCS CONFIGURE_DEPENDS src/tools/*.cpp)

foreach(tool_src ${TOOL_SRCS})
    get_filename_component(tool_name ${tool_src} NAME_WE)
    add_executable(${tool_name}
        ${tool_src}
        src/http/jwt.cpp
        src/http/jwt.h
    )
    target_link_libraries(${tool_name} Qt6::Core)
endforeach()

# -----------------------------------------
# RUNTIME-Deployment (TLS-Plugin + OpenSSL 3)
# -----------------------------------------
# Passe diese beiden Pfade an DEINE Installation an (oder setze sie im CMake-Dialog):
set(QT_PLUGINS_DIR "C:/Qt2/6.9.3/mingw_64/plugins" CACHE PATH "Qt plugins dir")
# OpenSSL 3 DLLs – Beispiel: MSYS2-MinGW-64
set(OPENSSL_RUNTIME_DIR "C:/Program Files/OpenSSL-Win64/bin" CACHE PATH "OpenSSL runtime dir")

if (WIN32)
  # TLS-Plugin qopensslbackend.dll kopieren
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
      $<TARGET_FILE_DIR:${PROJECT_NAME}>/tls
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${QT_PLUGINS_DIR}/tls/qopensslbackend.dll"
      $<TARGET_FILE_DIR:${PROJECT_NAME}>/tls/
  )
  # Optional: platform-Plugin qwindows.dll gleich mitkopieren
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
      $<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${QT_PLUGINS_DIR}/platforms/qwindows.dll"
      $<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms/
  )
  # OpenSSL 3 DLLs (libssl-3-x64.dll + libcrypto-3-x64.dll) neben die EXE
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${OPENSSL_RUNTIME_DIR}/libssl-3-x64.dll"
      $<TARGET_FILE_DIR:${PROJECT_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${OPENSSL_RUNTIME_DIR}/libcrypto-3-x64.dll"
      $<TARGET_FILE_DIR:${PROJECT_NAME}>
  )
endif()
