#ifndef FORMATO_DP_H
#define FORMATO_DP_H
#include <string>
namespace SRDP {
	class codidp {
	private:
		std::string requiere;
		std::string clavecita;
		bool coddp(std::string& docen, std::string& docsa);
		bool desdp(std::string& docen, std::string& docsa);
	public:
		codidp(std::string& clav);
		
	};
	class codirg {
	private:
		std::string clavecita2;
		bool codrg(std::string& docen, std::string& docsa);
		bool desrg(std::string& docen, std::string& docsa);
	public:
		codirg(std::string& cla);
	};
	namespace SRDPUtils {
		bool gen_gua_cla(std::string& arcgua, std::string& clavei);
		bool car_cla(std::string& archcar, std::string& clavei, int& pos);
		std::string gencla();
	}
}

#endif 