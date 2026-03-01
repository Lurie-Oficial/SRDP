#include "login.h"
#include "crypto.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstdlib>
#include <json.hpp>
using namespace std;
namespace fs = std::filesystem;
using json = nlohmann::json;
int logear::preparar_login() {
    fs::path ruac = fs::current_path();
    string cave = SRDP::CryptoUtil::generarClaveAleatoria(32);
    SRDP::CryptoMotor crypto("CNFigualaMicompañia");
    string nesesario = "Usuario: user\nContraseña: " + cave;
    ofstream mi_archi("Programa/Usuarios/user.txt");
    mi_archi << nesesario;
    mi_archi.close();
    ofstream doc(ruac / "Usuario_por_defecto.txt");
    doc << "El usuario por defecto es 'user', y la clave es: " << cave;
    crypto.cifrarArchivo("Programa/Usuarios/user.txt","Programa/Usuarios/user.rg");
    try {
        fs::remove("Programa/Usuarios/user.txt");
        throw runtime_error("Error inesperado");
    }
    catch (runtime_error& e) {
        cerr << "Exepcion capturada" << e.what() << endl;
    }
    return 0;
}
int logear::crear_json(fs::path directorio) {
    json j;
    j["Especificaciones"] = "Producto para crear registros\nUtilizelo con precaucion";
    j["Version"] = "1.0";
    j["Derechos"] = "Glicht Industries";

    ofstream archi(directorio/"SRDP_Informacion.json");
    if (archi.is_open()) {
        archi << j;
        archi.close();
        return 0;
    }
    else
    {
        cerr << "Hubo un error" << endl;
        return 1;
    }
}
int logear::crear(fs::path directorio) {
    fs::path ruy = "Programa/Usuarios";
    fs::path ruyt = "Programa/Registros";
    fs::path ruta = directorio;
    fs::path ruta1 = ruta / ruy;
    fs::path ruta2 = ruta / ruyt;
    bool crea1 = fs::create_directories(ruta1);
    bool crea2 = fs::create_directories(ruta2);
    if (!crea1) {
        cout << "Directorio de usuarios no pudo ser creado " << flush;
        if (fs::is_directory(ruta1)) {
            cout << "El directorio ya existia" << flush;
        }
        else {
            cout << "Hubo un error" << endl;
            return 1;
        }
    }
    if (!crea2) {
        cout << "Directorio de registros no pudo ser creado " << flush;
        if (fs::is_directory(ruta2)) {
            cout << "El directorio ya existia" << flush;
        }
        else {
            cout << "Hubo un error" << endl;
            return 2;
        }
    }

    return 0;
}
void logear::checar() {
    fs::path ruticima = fs::current_path();
    cout << "Verificando sistema..." << endl;
    cout << "[=         ] 1%\r" << flush;
    if (!fs::exists(ruticima / "Programa/Usuarios") || !fs::exists(ruticima / "Programa/Registros")) {
        int remi = crear(ruticima);
        switch (remi)
        {
        case  1:
            cout << "El creador devolvio 1" <<"\n Por favor cierre el programa o muevalo a otra carpeta\n" << flush;
            break;
        case 2:
            cout << "El creador devolvio 2" << "\n Por favor cierre el programa o muevalo a otra carpeta\n" << flush;
        default:
            break;
        }
    }
    cout << "[====      ] 40%\r" << flush;
    int sola = crear_json(ruticima);
    switch (sola)
    {
    case 1:
        cout << "La operacion devolvio 1" << "\nPor favor elimine todas las carpetas o mueva el programa de lugar\n" << flush;
        break;
    default:
        break;
    }
    cout << "[======    ] 60%\r" << flush;
    preparar_login();
    cout << "[==========] 100%" << flush;
#ifdef _WIN32
    system("cls");
#elif _WIN64
    system("cls");
#elif __linux__
    system("clear");
#endif 

    login();
}

bool logear::login() {
    bool correcto = false;
    string uno; string dos; bool seguir = false;
    do
    {
        cout << "Coloque el nombre del usuario: ";
        cin >> uno;
        string tres ="Programa/Usuarios/" + uno + ".rg";
        string cuatro = "Programa/Usuarios/" + uno + ".txt";
        if (fs::exists(tres)) {

            SRDP::CryptoMotor micodi("CNFigualaMicompañia");
            micodi.descifrarArchivo(tres,cuatro);
            ifstream mi_codigo(cuatro);
            string salida;
            string sal2;
            getline(mi_codigo, sal2);
            string cinco = "Usuario: " + uno;
            if (cinco == sal2) {
                cout << "\nUsuario verificado con exito" << endl;
                seguir = true;
            }
            else {
                cerr << "\nUsuario incorrecto\n";
            }
            if (seguir) {
                int lb = 2;
                int cl = 0;
                while (getline(mi_codigo, salida)) {
                    cl++;
                    if (cl == lb) {

                    }
                }
                string seis; cout << "Coloque la clave: "; cin >> seis; string siete = "Contraseña: " + seis; if (siete == salida) {
                    cout << "Clave correcta" << endl;
                    correcto = true;
                }
                else {
                    cout << "Clave incorrecta" << endl;
                }

                
            }
            fs::path traer = fs::current_path();
            mi_codigo.close();

            if (!fs::remove(traer / cuatro)) {
                cerr << "FALLO AL LIMPIAR SISTEMA" << endl;
            }
            cout << "Preparando programa" << "\n[";
                for (int i = 0; i <= 50; i++) {
                    cout << "#";
                }    
            cout << "] 100%\n";
        }
        else {
            cerr << "\nUsuario inexistente\n";
        }
    } while (!correcto);
    return true;
}

logear::logear() : ver("SRDP Sys-login vAlpha") {
    checar();
}
