cmake_minimum_required(VERSION 3.15)
project(srdp_linux_root)

# Forzar compiladores de Linux
if(WIN32)
    # No especificar compilador manualmente, dejar que CMake detecte
    # Solo asegurar que usamos el generador correcto
    message(STATUS "Configurando para Windows con MSVC")
endif()
# Solo incluir el subdirectorio
add_subdirectory(srdp_linux)