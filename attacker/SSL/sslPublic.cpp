
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




int SSLPublic::freeSSLPort() {
	int result = 0;
	int cnt = 0;
	char cmd[1024];
	wsprintfA(cmd, "netstat -ano |findstr :443 > cmd.txt");
	result = system(cmd);

	char* data = 0;
	int filesize = 0;
	result = FileOper::fileReader("cmd.txt", &data, &filesize);
	if (filesize)
	{
		char* hdr = data;
		char* end = hdr;
		while (hdr < (data + filesize) && end < (data + filesize))
		{

			char line[1024];
			end = strstr(hdr, "\r\n");
			if (end)
			{

				int len = end - hdr;
				memcpy(line, hdr, len);
				line[len] = 0;
				end += 2;
				hdr = end;
			}
			else {
				lstrcpyA(line, hdr);
				hdr = data + filesize;
				end = hdr;
			}

			char* pos = strstr(line, "TCP");
			if (pos)
			{
				pos += 3;
				while (*pos)
				{
					if (*pos == 0x20)
					{
						pos++;
					}
					else {
						break;
					}
				}

				char local[1024];
				local[0] = 0;
				char* last = strchr(pos, ' ');
				if (last)
				{
					int locallen = last - pos;
					memcpy(local, pos, locallen);
					local[locallen] = 0;
				}

				if (strstr(local, ":443"))
				{
					char* id = line + lstrlenA(line);
					char* id_end = id;
					while (*id != 0x20)
					{
						id--;
					}
					char strid[64];
					int idlen = id_end - id;
					memcpy(strid, id, idlen);
					strid[idlen] = 0;
					DWORD dwid = atoi(strid);

					char kill[1024];
					wsprintfA(kill, "taskkill /f /pid %u", dwid);
					system(kill);
					printf("kill process pid:%d address:%s\r\n", dwid, local);
					cnt++;
				}
			}

		}
	}

	return cnt;
}