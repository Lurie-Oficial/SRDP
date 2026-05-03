# SRDP (Sistema de Registro de Datos Personales)

## Propósito

**SRDP** es un **Sistema** creado para crear registros de datos personales.
Esto funciona con un cifrado AES-256-GCM.
Por ahora todas sus funcionalidades no estan incluidas y esta en un version temprana del desarrollo.

## Instalación

Este sistema esta diseñado para las plataformas de Windows y Linux.

## Requisitos

- **Windows:** Visual Studio 2022 (Build Tools), vcpkg, CMake 3.15+
- **Linux:** g++ 11+, CMake 3.15+, OpenSSL

### Windows
 
```powershell
git clone https://github.com/Lurie-Oficial/SRDP.git
cd SRDP
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/ruta/a/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build .
```
*Nota: Reemplaza C:/ruta/a/vcpkg con la ubicación real de vcpkg.*

### Linux
```bash
git clone https://github.com/Lurie-Oficial/SRDP
cd SRDP
mkdir build && cd build
cmake ..
make
```

## Uso
El sistema no esta completo todavia.

## Licencia
Proyecto bajo la licencia MIT. 
Consulta LICENSE para más información.

## Autor
### **Lurie** 

En GitHub: [Lurie-Oficial.](github.com/Lurie-Oficial)