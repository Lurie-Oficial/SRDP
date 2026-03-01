#include "formato_dp.h"
#include "crypto.h"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <random>

using namespace std;
namespace fs = std::filesystem;
namespace SRDP {
    string SRDPUtils::gencla() {
		string lts = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		random_device rd;
		mt19937 gen(rd());
		uniform_int_distribution<> dist(0, lts.size() - 1);
		string clace = "";
		for (int i = 0; i < 12; i++) {
			int indice = dist(gen);
			clace.push_back(lts[indice]);
		}
		return clace;
	}
	bool SRDPUtils::gen_gua_cla(string& arcgua, string& clavei) {
		SRDP::CryptoMotor enc("asa");
		vector<string> contras(3);
		for (int i = 0; i < 3; i++) {
			string cavel = SRDPUtils::gencla();
			string con = enc.cifrarTexto(cavel);
			contras.push_back(con);
		}
		ofstream llaves(fs::current_path() / "SRDP_llaves.key");
		if (llaves.is_open()) {
			for (const auto& elem : contras) {
				llaves << elem << endl;
			}
		}
		return true;
	}
	codidp::codidp(std::string& clav) : requiere("Un S.O. que no sea Mac OS") {
		clavecita = clav;
	}
	bool codidp::coddp(string& docen, string& docsa) {
		
		return false;
	}
}