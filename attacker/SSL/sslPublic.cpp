
#include "sslPublic.h"
#include "../attacker.h"
#include "../FileOper.h"
#include <vector>
#include <iostream>
#include <string>

using namespace std;

WORKERCONTROL gWorkControl;

vector <string> gHostAttackList;

char G_USERNAME[64];

SSLPublic::SSLPublic(vector<string>list) {
	if (mInstance)
	{
		return;
	}

	mInstance = this;
	gHostAttackList = list;
}


SSLPublic::~SSLPublic() {

}


int SSLPublic::isTargetHost(string host) {
	unsigned int targetlen = gHostAttackList.size();
	for (unsigned int i = 0; i < targetlen; i++) {
		if (strstr(host.c_str(), gHostAttackList[i].c_str())) {
			return TRUE;
		}
	}

	return FALSE;
}

int SSLPublic::prepareCertChain(string certname) {
	int ret = 0;
	string  curpath = gLocalPath + CA_CERT_PATH +"\\";

	string crtname = curpath + certname + ".crt";
	string midcrtname = curpath+ certname + ".mid.crt";
	string crtchainname = curpath+ certname + ".chain.crt";
	string cafn = curpath + DIGICERTCA;
	if (FileOper::isFileExist(crtchainname))
	{
		DeleteFileA(crtchainname.c_str());
	}

	string cmd = "cmd /c type " + crtname + " >> " + crtchainname;
	ret = system(cmd.c_str());
	cmd = "cmd /c echo.>> " + crtchainname;
	ret = system(cmd.c_str());

	cmd = "cmd /c type " + midcrtname + " >> " + crtchainname;
	ret = system(cmd.c_str());
	cmd = "cmd /c echo.>> " + crtchainname;
	ret = system(cmd.c_str());

	cmd = "cmd /c type " + cafn + " >> " + crtchainname;
	ret = system(cmd.c_str());
	cmd = "cmd /c echo.>> " + crtchainname;
	ret = system(cmd.c_str());

	return 0;

}


