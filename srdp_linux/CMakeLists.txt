cmake_minimum_required(VERSION 3.15)
project(srdp_linux LANGUAGES CXX)

# Estándar C++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# En Linux/WSL: si se usa el toolchain de vcpkg para Windows (x64-windows),
# se inyectan flags MSVC como "/utf-8" y rutas de includes Windows, y GCC/Clang
# lo interpreta como archivo de entrada. Detectamos y fallamos con mensaje claro.
if(UNIX AND NOT APPLE)
    if(DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "windows")
        message(FATAL_ERROR
            "Estás configurando en Linux/WSL con VCPKG_TARGET_TRIPLET='${VCPKG_TARGET_TRIPLET}'. "
            "Eso fuerza flags de MSVC (ej: /utf-8) y rompe GCC/Clang. "
            "Usa un triplet Linux (ej: x64-linux) o instala/usa vcpkg dentro de WSL.")
    endif()
endif()

# Además, por si quedaron flags MSVC en variables globales/caché, los limpiamos
# explícitamente cuando NO es MSVC.
if(NOT MSVC)
    foreach(_flag "/utf-8" "/EHsc" "/W4")
        foreach(_var
            CMAKE_C_FLAGS
            CMAKE_C_FLAGS_DEBUG
            CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_MINSIZEREL
            CMAKE_CXX_FLAGS
            CMAKE_CXX_FLAGS_DEBUG
            CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_RELWITHDEBINFO
            CMAKE_CXX_FLAGS_MINSIZEREL
        )
            if(DEFINED ${_var})
                string(REPLACE "${_flag}" "" ${_var} "${${_var}}")
                # Persistir también en caché si aplica
                if(${_var} MATCHES "CMAKE_.*_FLAGS")
                    set(${_var} "${${_var}}" CACHE STRING "" FORCE)
                endif()
            endif()
        endforeach()
    endforeach()
endif()

# ============================
# Dependencias (FTXUI) OBLIGATORIO
# ============================
#
# En WSL/Linux, evita usar `find_package(ftxui)` si pudiera resolver a un FTXUI
# de vcpkg Windows (x64-windows), lo cual inyecta flags de MSVC como `/utf-8`
# y rompe el build con GCC/Clang.

set(_SRDP_FTXUI_NEEDS_FETCH OFF)

if(UNIX AND NOT APPLE)
    # Evita que en WSL se resuelva FTXUI desde el vcpkg de Windows (x64-windows),
    # que inyecta flags MSVC como "/utf-8" y rompe el build con GCC/Clang.
    if(EXISTS "/mnt/c/vcpkg/installed/x64-windows")
        list(APPEND CMAKE_IGNORE_PATH "/mnt/c/vcpkg/installed/x64-windows")
    endif()

    # En Linux intentamos usar una instalación ya presente,
    # pero evitamos el caso "vcpkg x64-windows" que rompe con flags MSVC (/utf-8).
    find_package(ftxui QUIET)
    if(NOT ftxui_FOUND)
        set(_SRDP_FTXUI_NEEDS_FETCH ON)
    elseif(DEFINED ftxui_DIR AND ftxui_DIR MATCHES "x64-windows")
        set(_SRDP_FTXUI_NEEDS_FETCH ON)
    endif()
else()
    find_package(ftxui QUIET)
    if(NOT ftxui_FOUND)
        set(_SRDP_FTXUI_NEEDS_FETCH ON)
    endif()
endif()

if(_SRDP_FTXUI_NEEDS_FETCH)
    include(FetchContent)

    # Mantener el sub-build estable y rápido
    set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(FTXUI_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        ftxui
        URL https://github.com/ArthurSonzogni/FTXUI/archive/refs/tags/v6.1.9.tar.gz
    )
    FetchContent_MakeAvailable(ftxui)
endif()

# Validar que los targets existen (obligatorio)
if(NOT TARGET ftxui::screen OR NOT TARGET ftxui::dom OR NOT TARGET ftxui::component)
    message(FATAL_ERROR
        "FTXUI es obligatorio pero no pudo configurarse. "
        "Asegura acceso a git/internet (FetchContent) o instala FTXUI correctamente.")
endif()

# Buscar OpenSSL (NUEVO)
find_package(OpenSSL REQUIRED)
message(STATUS "🔐 OpenSSL encontrado: ${OPENSSL_VERSION}")

# Configuración multiplataforma básica
if(WIN32)
    message(STATUS "🔧 Configurando para Windows")
    set(EXECUTABLE_NAME "srdp_linux.exe")
    add_definitions(-DSRDPLINUX_WINDOWS -D_CRT_SECURE_NO_WARNINGS)
else()
    message(STATUS "🔧 Configurando para Unix/Linux")
    set(EXECUTABLE_NAME "srdp_linux")
    add_definitions(-DSRDPLINUX_UNIX)
    if(APPLE)
        add_definitions(-DSRDPLINUX_MACOS)
    else()
        add_definitions(-DSRDPLINUX_LINUX)
    endif()
endif()

# Archivos principales
set(SRDP_SOURCES
    srdp_linux.cpp
    "codigoextra/src/login.cpp"
    "codigoextra/src/crypto.cpp"
    "codigoextra/src/formato_dp.cpp")  # NOTA: eliminé crypto.cpp duplicado

set(SRDP_HEADERS
    srdp_linux.h
    "codigoextra/incluir/login.h"
    "codigoextra/incluir/crypto.h"
    "codigoextra/incluir/formato_dp.h")

add_executable(${PROJECT_NAME} ${SRDP_SOURCES} ${SRDP_HEADERS})

if(WIN32)
    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/recursos.rc")
endif()

# Propiedades
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "srdp_linux"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Includes
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/codigoextra/incluir 
    ${CMAKE_CURRENT_SOURCE_DIR}/codigoextra/src 
    ${OPENSSL_INCLUDE_DIR}  # NUEVO: Include de OpenSSL
)

# Opciones de compilación
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /EHsc /utf-8)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)
endif()

# Librerías del sistema y OpenSSL (MODIFICADO)
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE 
        Threads::Threads
        OpenSSL::SSL      # NUEVO: OpenSSL SSL
        OpenSSL::Crypto   # NUEVO: OpenSSL Crypto
    )
elseif(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE 
        OpenSSL::SSL      # NUEVO: OpenSSL SSL
        OpenSSL::Crypto   # NUEVO: OpenSSL Crypto
    )
endif()

# Link de FTXUI (obligatorio)
target_link_libraries(${PROJECT_NAME} PRIVATE
    ftxui::screen
    ftxui::dom
    ftxui::component
)

message(STATUS "✅ ${PROJECT_NAME} listo para compilar en ${CMAKE_SYSTEM_NAME}")