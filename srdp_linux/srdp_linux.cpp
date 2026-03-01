// srdp_linux.cpp: define el punto de entrada de la aplicación.
//

#include "srdp_linux.h"
#include "login.h"
#include "formato_dp.h"
using std::cout;
using std::cin;
using std::endl;
using std::string;
using std::ofstream;
string sa = "\n";
string es = " ";
bool op = true;

struct base {
    string menu() {
        string uno = "  ==== MENU ====  ";
        string dos = "1. Crear un registro";
        string tres = "2. Listar registros";
        string cuatro = "3. Cargar un registro";
        string cinco = "4. Eliminar un registro";
        string seis = "5.Salir de la plataforma";
        return sa + uno + sa + dos + sa + tres + sa + cuatro + sa + cinco + sa + seis;
    }
    void def_ac() {
        string ac;
        cout << sa << "Elije una opcion: ";
        cin >> ac;
        if (ac == "1") {
            cout << "hola" << endl;
        }
        else if (ac == "5") {
            cout << "Hasta pronto" << endl;
            op = false;
        }
        {

        }
    }
};

static int ver() {
    int sistem;
#ifdef _WIN32
    sistem = 1;
#elif _WIN64
    sistem = 1;
#elif __linux__
    sistem = 2;
#endif

    return sistem;
}
static void ver_pausa() {
    int sistema;
#ifdef _WIN32
    sistema = 1;
#elif __linux__
    sistema = 2;
#endif
    if (sistema == 1) {
        cout << " " << endl;
        system("pause");
    }
    else if (sistema == 2) { cout << sa << "Presiona Enter para continuar..."; cin.ignore(); cin.get(); }
}
int main() {
    int a = ver();
    base fun;
    string minu = fun.menu();
    string texto;
#ifdef _WIN32
    system("cls");
#elif _WIN64
    system("cls");
#elif __linux__
    system("clear");
#endif 
    if (a == 1) {
        texto = "Bienvenido SRDP potenciado con C++\n";
    }
    else if (a == 2) {
        texto = "Bienvenido a SRDP para Linux, potenciado con C++\n";
    }

    cout << texto << endl;
    logear art;
    while (op)
    {
        cout << minu << endl;
        fun.def_ac();
        ver_pausa();
    }
    return 0;
}
