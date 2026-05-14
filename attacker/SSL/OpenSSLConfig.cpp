

#include "../Utils/Tools.h"
#include "sslPublic.h"
#include <Windows.h>
#include <lm.h>
#include <Winternl.h>
#include <iostream>
#include <DbgHelp.h>
#include "opensslconfig.h"
#include "../FileOper.h"
#include <string>

using namespace std;





int OpenSSLConfig::InitOpenssl(int control) {
	int ret = 0;

	GetOpensslPath();

	if (control& OPENSSL_CLEAR_PATH)
	{
		ret = clearOpenssl();
		printf("clear Openssl complete\r\n");	
	}

	ret = FileOper::delFolder((char*)(gOpensslPath + "demoCA/").c_str());

	ret = CreateDirectoryA((gOpensslPath + "demoCA/").c_str(),0);

	ret = CreateDirectoryA((gOpensslPath + "demoCA/mycerts/").c_str(), 0);

	log("mkdir:%s\r\n", (gOpensslPath + "demoCA/").c_str());

	ret = CreateDirectoryA((gOpensslPath + "demoCA/newcerts/").c_str(),0);

	log("mkdir:%s\r\n", (gOpensslPath + "demoCA/newcerts/").c_str());

	HANDLE hf_idx = CreateFileA((gOpensslPath + "demoCA/index.txt").c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf_idx != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hf_idx);
		log("create file:%s\r\n", (gOpensslPath + "demoCA/index.txt").c_str());
	}

	HANDLE hf_idx_attr = CreateFileA((gOpensslPath + "demoCA/index.txt.attr").c_str(), GENERIC_WRITE,0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf_idx_attr != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hf_idx_attr, 0);
		if (filesize == 0)
		{
			DWORD dwcnt = 0;
			char * strattr = "unique_subject = yes\r\n";
			ret = WriteFile(hf_idx_attr, strattr, lstrlenA(strattr), &dwcnt, 0);

			log("create file:%s\r\n", (gOpensslPath + "demoCA/index.txt.attr").c_str());
		}

		CloseHandle(hf_idx_attr);
	}

	HANDLE hf_serial = CreateFileA((gOpensslPath + "demoCA/serial").c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf_serial != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hf_serial, 0);
		if (filesize == 0)
		{
			DWORD dwcnt = 0;
			char* strserial = "01\r\n";
			ret = WriteFile(hf_serial, strserial, strlen(strserial), &dwcnt, 0);
			log("create file:%s\r\n", (gOpensslPath + "demoCA/serial").c_str());
		}

		CloseHandle(hf_serial);
	}

	HANDLE hf_cfg = CreateFileA((gOpensslPath + OPENSSLCONFIG_FILENAME).c_str(), GENERIC_READ|GENERIC_WRITE, 0, 0,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf_cfg != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hf_cfg, 0);
		char * lpdata = new char[filesize + 1024];
		DWORD dwcnt = 0;
		ret = ReadFile(hf_cfg, lpdata, filesize, &dwcnt, 0);
		if (ret )
		{
			string conf = string(lpdata, filesize);
			while (TRUE)
			{
				string pathflag = "./demoCA";
				int pos = conf.find(pathflag.c_str());
				if (pos != -1)
				{
					string demopath = gOpensslPath + "demoCA";
					conf = conf.replace(pos, strlen(pathflag.c_str()), demopath);
				}
				else {
					break;
				}
			}

			ret = SetFilePointer(hf_cfg, 0, 0, FILE_BEGIN);
			ret = WriteFile(hf_cfg, conf.c_str(), conf.length(), &dwcnt, 0);
			SetEndOfFile(hf_cfg);
		}

		delete[] lpdata;
		CloseHandle(hf_cfg);
	}
	else {
		log("%s %d CreateFile:%s error\r\n",__FUNCTION__,__LINE__, (gOpensslPath + OPENSSLCONFIG_FILENAME).c_str());
	}

	return 0;
}




string OpenSSLConfig::getOpensslInstallPath()
{
	int ret = 0;
	int cpubits = Tools::getSysBits();
	string apppath = "";
	if (cpubits == 64)
	{
		ret = Tools::getInstallPath(cpubits, "OpenSSL", apppath);
		if (ret <= 0)
		{
			ret = Tools::getInstallPath(32, "OpenSSL", apppath);
		}
	}
	else {
		ret = Tools::getInstallPath(cpubits, "OpenSSL", apppath);
	}

	return apppath;
}


void OpenSSLConfig::GetOpensslPath() {
	int ret = 0;
	gOpensslRoot = OpenSSLConfig::getOpensslInstallPath();
	if (gOpensslRoot == "")
	{
		ret = OpenSSLConfig::getOpensslPathFromCfg();
		if (gOpensslRoot == "")
		{
			MessageBoxA(0, "not install openssl", "not install openssl", MB_OK);
			ExitProcess(0);
		}
	}
	gOpensslPath = gOpensslRoot;

	if (gOpensslPath.back() == '\\')
	{
		gOpensslPath = gOpensslPath + "bin\\";
	}
	else {
		gOpensslPath = gOpensslPath + "\\bin\\";
	}

	gOpensslWinPath = gOpensslPath;
	gOpensslPath = Public::winPath2Linux(gOpensslWinPath.c_str());

	ret = OpenSSLConfig::addRunPath(gOpensslWinPath);

	log("%s %d openssl path:%s\r\n", __FUNCTION__, __LINE__, gOpensslPath.c_str());
}

int OpenSSLConfig::getOpensslPathFromCfg() {
	int ret = 0;
	string filename = gLocalPath  + OPENSSLPATH_FILENAME;

	HANDLE hf = CreateFileA(filename.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		log("not found openssl config file:%s\r\n", filename.c_str());
		return FALSE;
	}

	int filesize = GetFileSize(hf, 0);
	char * lpbuf = new char[filesize + 1024];
	DWORD dwcnt = 0;
	ret = ReadFile(hf, lpbuf, filesize, &dwcnt, 0);
	CloseHandle(hf);
	*(lpbuf + filesize) = 0;

	char * hdr = strstr(lpbuf, "openssl_path:");
	if (hdr)
	{
		hdr += strlen("openssl_path:");
	}
	else {
		return 0;
	}
	char * end = strstr(hdr, "\r\n");
	if (end)
	{
		gOpensslPath = string(hdr, end - hdr);
		if (gOpensslPath.back() == '\\')
		{
			gOpensslPath = gOpensslPath ;
		}
		else {
			gOpensslPath = gOpensslPath + "\\" ;
		}
	}
	else {
		gOpensslPath = string(hdr);
		if (gOpensslPath.back() == '\\')
		{
			gOpensslPath = gOpensslPath ;
		}
		else {
			gOpensslPath = gOpensslPath + "\\" ;
		}
	}

	delete[] lpbuf;
	return FALSE;
}



int OpenSSLConfig::clearOpenssl() {

	int ret = 0;
	char opensslpath[MAX_PATH] = { 0 };
	lstrcpyA(opensslpath, gOpensslPath.c_str());
	for (unsigned int i = 0; i < gOpensslPath.length(); i ++)
	{
		if (opensslpath[i] == '/')
		{
			opensslpath[i] = '\\';
		}
	}
	
	string path = string("\"") + string(opensslpath) + "demoCA\\index.txt.attr" + string("\"");
	string cmd = "cmd /c del /F /S /Q " + path;
	ret = system(cmd.c_str());

	path = string("\"") + string(opensslpath) + "demoCA\\index.txt" + string("\"");
	cmd = "cmd /c del /F /S /Q "+ path;
	ret = system(cmd.c_str());

	path = string("\"") + string(opensslpath) + "demoCA\\serial" + string("\"");
	cmd = "cmd /c del /F /S /Q "  + path;
	ret = system(cmd.c_str());

	path = string("\"") + string(opensslpath) + "demoCA\\*.*" + string("\"");
	cmd = "cmd /c del /F /S /Q " + path;
	ret = system(cmd.c_str());

	path = string("\"") + string(opensslpath) + "demoCA\\*" + string("\"");
	cmd = "cmd /c del /F /S /Q " + path;
	ret = system(cmd.c_str());

	path = string("\"") + string(opensslpath) +"demoCA\\newcerts\\*.*" + string("\"");
	cmd = "cmd /c del /F /S /Q " + path;
	ret = system(cmd.c_str());

	path = string("\"") + string(opensslpath) + "demoCA\\mycerts\\*.*" + string("\"");
	cmd = "cmd /c del /F /S /Q " + path;
	ret = system(cmd.c_str());
	//demoCA/newcerts/
	//demoCA/index.txt
	//demoCA/serial
	
	//string cmd = "del /F /S /Q " + string(opensslpath) + "/demoCA";
	//int ret = WinExec(cmd.c_str(), SW_HIDE);

	path = string("\"") + string(gLocalPath) + CERT_PATH +  "\\*.*" + string("\"");
	cmd = "cmd /c del /F /S /Q " + path;
	ret = WinExec(cmd.c_str(), SW_HIDE);
	return ret;
}


//C:\OpenSSL-Win32\bin;
int OpenSSLConfig::addRunPath(string path) {

	HKEY hKey = 0;
	const wchar_t *key = L"System\\CurrentControlSet\\Control\\Session Manager\\Environment";

	int ret = 0;

	ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | KEY_WRITE, &hKey);
	if (ret != ERROR_SUCCESS)
	{
		log("%s %d error\r\n",__FUNCTION__,__LINE__);
		return -1;
	}

	DWORD dwType = REG_SZ;
	wchar_t data[0x1000] = {0};
	DWORD datalen = sizeof(data);
	ret = RegQueryValueExW(hKey, L"Path", NULL, &dwType, (LPBYTE)data, &datalen);
	if (ret != ERROR_SUCCESS)
	{
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		RegCloseKey(hKey);
		return -1;
	}

	wchar_t wpath[1024];
	int wpathlen = MultiByteToWideChar(CP_ACP, 0, path .c_str(), -1, wpath, sizeof(wpath)/sizeof(wchar_t) );
	*(WORD*)(wpath + wpathlen) = 0;

	if (wcsstr(data, wpath) )
	{
		log("openssl path:%ws already in system environment path\r\n", wpath);
		RegCloseKey(hKey);
		return TRUE;
	}

	//windows server is all in unicode
	//REG_EXPAND_SZ与REG_MULTI_SZ都使用unicode编码表示
	wpathlen = MultiByteToWideChar(CP_ACP, 0, (";" + path + ";").c_str(), -1, wpath, sizeof(wpath)/sizeof(wchar_t) );
	*(WORD*)(wpath + wpathlen) = 0;
	wcscat(data, wpath);
	ret = RegSetValueExW(hKey, L"Path", NULL, dwType, (const unsigned char *)data, wcslen(data)*2);	
	RegCloseKey(hKey);
	if (ret != ERROR_SUCCESS)
	{
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		return -1;
	}
	
	return 0;
}





