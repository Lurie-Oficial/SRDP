cmake_minimum_required(VERSION 3.15)
project(srdp_linux LANGUAGES CXX)

# Estándar C++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /EHsc)
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

message(STATUS "✅ ${PROJECT_NAME} listo para compilar en ${CMAKE_SYSTEM_NAME}")