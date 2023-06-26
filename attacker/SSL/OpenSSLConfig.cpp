

#include "../Utils/Tools.h"
#include "sslPublic.h"
#include <Windows.h>
#include <lm.h>
#include <Winternl.h>
#include <iostream>
#include <DbgHelp.h>
#include "opensslconfig.h"

#include <string>

using namespace std;


int OpenSSLConfig::initOpensslPath(int control) {
	int ret = 0;

	if (control)
	{
		ret = reset();
		printf("reset openssl param over\r\n");	
	}

	ret = CreateDirectoryA((gOpensslPath + "demoCA/").c_str(),0);

	printf("mkdir:%s\r\n", (gOpensslPath + "demoCA/").c_str());

	ret = CreateDirectoryA((gOpensslPath + "demoCA/newcerts/").c_str(),0);

	printf("mkdir:%s\r\n", (gOpensslPath + "demoCA/newcerts/").c_str());

	HANDLE hf = CreateFileA((gOpensslPath + "demoCA/index.txt").c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hf);
		printf("make file:%s\r\n", (gOpensslPath + "demoCA/index.txt").c_str());
	}

	HANDLE hfindexattr = CreateFileA((gOpensslPath + "demoCA/index.txt.attr").c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfindexattr != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hfindexattr, 0);
		if (filesize == 0)
		{
			DWORD dwcnt = 0;
			ret = WriteFile(hfindexattr, "unique_subject = yes\r\n", lstrlenA("unique_subject = yes\r\n"), &dwcnt, 0);

			printf("make file:%s\r\n", (gOpensslPath + "demoCA/index.txt.attr").c_str());
		}

		CloseHandle(hfindexattr);
	}

	hf = CreateFileA((gOpensslPath + "demoCA/serial").c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hf, 0);
		if (filesize == 0)
		{
			DWORD dwcnt = 0;
			ret = WriteFile(hf, "01\r\n", strlen("01\r\n"), &dwcnt, 0);
			printf("make file:%s\r\n", (gOpensslPath + "demoCA/serial").c_str());
		}

		CloseHandle(hf);
	}

	hf = CreateFileA((gOpensslPath + OPENSSLCONFIG_FILENAME).c_str(), GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf != INVALID_HANDLE_VALUE)
	{
		int filesize = GetFileSize(hf, 0);
		char * lpdata = new char[filesize + 1024];
		DWORD dwcnt = 0;
		ret = ReadFile(hf, lpdata, filesize, &dwcnt, 0);
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

			ret = SetFilePointer(hf, 0, 0, FILE_BEGIN);
			ret = WriteFile(hf, conf.c_str(), conf.length(), &dwcnt, 0);
		}

		delete[] lpdata;
		CloseHandle(hf);
	}
	else {
		printf("CreateFile error:%s\r\n", (gOpensslPath + OPENSSLCONFIG_FILENAME).c_str());
	}

	return 0;
}




string OpenSSLConfig::getOpenSSLPath()
{
	int ret = 0;
	int cpubits = Tools::GetCpuBits();
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




int OpenSSLConfig::getOpenSSLPathFromCfg() {
	int ret = 0;
	string filename = gLocalPath  + OPENSSLPATH_FILENAME;

	HANDLE hf = CreateFileA(filename.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		printf("not found openssl path config\r\n");
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
	char * end = strstr(hdr, "\r\n");
	if (end)
	{
		gOpensslPath = string(hdr, end - hdr);
		if (gOpensslPath.back() == '\\')
		{
			gOpensslPath = gOpensslPath /*+ OPENSSLCONFIG_FILENAME*/;
		}
		else {
			gOpensslPath = gOpensslPath + "\\" /*+ OPENSSLCONFIG_FILENAME*/;
		}
	}
	else {
		gOpensslPath = string(hdr);
		if (gOpensslPath.back() == '\\')
		{
			gOpensslPath = gOpensslPath /*+ OPENSSLCONFIG_FILENAME*/;
		}
		else {
			gOpensslPath = gOpensslPath + "\\" /*+ OPENSSLCONFIG_FILENAME*/;
		}
	}

	delete[] lpbuf;
	return FALSE;
}



int OpenSSLConfig::reset() {
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
	
	string cmd = "cmd /c del /F /S /Q " + string(opensslpath) + "demoCA\\index.txt.attr";
	//ret = WinExec(cmd.c_str(), SW_HIDE);
	ret = system(cmd.c_str());

	cmd = "cmd /c del /F /S /Q " + string(opensslpath) + "demoCA\\index.txt";
	//ret = WinExec(cmd.c_str(), SW_HIDE);
	ret = system(cmd.c_str());

	cmd = "cmd /c del /F /S /Q " + string(opensslpath) + "demoCA\\serial";
	//ret = WinExec(cmd.c_str(), SW_HIDE);
	ret = system(cmd.c_str());

	cmd = "cmd /c del /F /S /Q " + string(opensslpath) + "demoCA\\*.*";
	//ret = WinExec(cmd.c_str(), SW_HIDE);
	ret = system(cmd.c_str());

	cmd = "cmd /c del /F /S /Q " + string(opensslpath) + "demoCA\\*";
	//ret = WinExec(cmd.c_str(), SW_HIDE);
	ret = system(cmd.c_str());

	cmd = "cmd /c del /F /S /Q " + string(opensslpath) + "demoCA\\newcerts\\*.*";
	//ret = WinExec(cmd.c_str(), SW_HIDE);
	ret = system(cmd.c_str());

	//demoCA/newcerts/
	//demoCA/index.txt
	//demoCA/serial
	//string cmd = "del /F /S /Q " + string(opensslpath) + "/demoCA";
	//int ret = WinExec(cmd.c_str(), SW_HIDE);


	cmd = "cmd /c del /F /S /Q " + gLocalPath + CERT_PATH  + "\\*.*";
	ret = WinExec(cmd.c_str(), SW_HIDE);
	return ret;
}


//C:\OpenSSL-Win32\bin;
int OpenSSLConfig::addSystemPath(string path) {

	HKEY hKey = 0;
	const wchar_t *key = L"System\\CurrentControlSet\\Control\\Session Manager\\Environment";

	int ret = 0;

	ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | KEY_WRITE, &hKey);
	if (ret != ERROR_SUCCESS)
	{
		printf("addSystemPath RegOpenKeyEx error\r\n");
		return -1;
	}

	DWORD dwType = REG_SZ;
	wchar_t data[0x4000] = {0};
	DWORD datalen = sizeof(data);
	ret = RegQueryValueExW(hKey, L"Path", NULL, &dwType, (LPBYTE)data, &datalen);
	if (ret != ERROR_SUCCESS)
	{
		printf("addSystemPath RegQueryValueEx error\r\n");
		RegCloseKey(hKey);
		return -1;
	}

	wchar_t wpath[1024];
	int wpathlen = MultiByteToWideChar(CP_ACP, 0, path .c_str(), -1, wpath, sizeof(wpath) );
	*(WORD*)(wpath + wpathlen) = 0;

	if (wcsstr(data, wpath) )
	{
		printf("openssl path exist already\r\n");
		RegCloseKey(hKey);
		return TRUE;
	}

	//windows server is all in unicode
	//REG_EXPAND_SZ与REG_MULTI_SZ实际上都是使用unicode编码表示的
	wpathlen = MultiByteToWideChar(CP_ACP, 0, (";" + path + ";").c_str(), -1, wpath, sizeof(wpath));
	*(WORD*)(wpath + wpathlen) = 0;
	wcscat(data, wpath);
	ret = RegSetValueExW(hKey, L"Path", NULL, dwType, (const unsigned char *)data, wcslen(data)*2);	//must use as char with wchar_t
	RegCloseKey(hKey);
	if (ret != ERROR_SUCCESS)
	{
		printf("addSystemPath RegSetValueEx error\r\n");
		return -1;
	}
	
	printf("addSystemPath set path:%s ok\r\n",path.c_str());
	return 0;
}