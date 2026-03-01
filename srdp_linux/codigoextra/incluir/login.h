#ifndef LOGIN_H
#define LOGIN_H
#include <string>
#include <filesystem>
class logear {
private:
	std::string ver;
	int crear(std::filesystem::path directorio);
	int crear_json(std:: filesystem::path directorio);
	int preparar_login();
	bool login();
public:
	logear();
	 void checar();
};

#endif 