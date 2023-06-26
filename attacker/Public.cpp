

#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <iostream>
#include "Public.h"
#include "attacker.h"
#include "cipher/zip.h"
#include "HttpUtils.h"
#include "ssl/sslPublic.h"


using namespace std;




int Public::zipFile(string inzipfn, string srcfn, string zipfn) {
	ZRESULT ret = 0;
	HZIP hz = CreateZip((char*)zipfn.c_str(), 0);
	if (hz)
	{
		ret = ZipAdd(hz, inzipfn.c_str(), srcfn.c_str());
		CloseZip(hz);
		return TRUE;
	}

	return FALSE;
}


int Public::zipFiles(vector<string> inzipfns, vector<string> srcfns, string zipfn) {
	ZRESULT ret = 0;
	HZIP hz = CreateZip((char*)zipfn.c_str(), 0);
	if (hz)
	{
		for (int i = 0; i < inzipfns.size(); i++)
		{
			ret = ZipAdd(hz, inzipfns[i].c_str(), srcfns[i].c_str());
		}

		CloseZip(hz);
		return TRUE;
	}

	return FALSE;
}

string Public::getDateTime() {
	SYSTEMTIME sttime = { 0 };
	GetLocalTime(&sttime);

	char sztime[MAX_PATH] = { 0 };
	int len = wsprintfA(sztime, "%u/%u/%u %u:%u:%u", sttime.wYear, sttime.wMonth, sttime.wDay, sttime.wHour, sttime.wMinute, sttime.wSecond);
	return string(sztime);
}






int Public::getstring(char* flag, char* endflag, char* lpdata, char* lpdst, int start) {
	int flaglen = lstrlenA(flag);
	char* lphdr = strstr(lpdata, flag);
	if (lphdr)
	{
		if (start)
		{
			lphdr += flaglen;
		}

		char* lpend = strstr(lphdr, endflag);
		if (lpend)
		{
			int len = lpend - lphdr;
			memmove(lpdst, lphdr, len);
			*(lpdst + len) = 0;
			return len;
		}
	}
	return FALSE;
}


DWORD Public::GetLocalIpAddress()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = { 0 };
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		return FALSE;
	}

	char local[MAX_PATH] = { 0 };
	int iRet = gethostname(local, sizeof(local));
	if (iRet)
	{
		return FALSE;
	}
	hostent* ph = gethostbyname(local);
	if (ph == NULL)
	{
		return FALSE;
	}

	in_addr addr = { 0 };
	memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr));
	if (addr.S_un.S_addr == 0)
	{
		return FALSE;
	}

	char szip[MAX_PATH] = { 0 };
	unsigned char cip[4] = { 0 };
	memmove(cip, &addr.S_un.S_addr, 4);
	int ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);
	printf("get ip from hostname:%s\r\n", szip);

	return addr.S_un.S_addr;
}


string Public::winPath2Linux(const char* winpath) {
	char linuxpath[1024];
	lstrcpyA(linuxpath, winpath);

	for (int i = 0; i < lstrlenA(winpath); i++)
	{
		if (winpath[i] == '\\')
		{
			linuxpath[i] = '/';
		}
	}

	return string(linuxpath);
}

string Public::getpath() {
	char szcurdir[MAX_PATH] = { 0 };

	int ret = 0;
	if (gLocalPath == "")
	{
		int len = GetCurrentDirectoryA(MAX_PATH, szcurdir);
		*(szcurdir + len) = 0;
		gLocalPath = szcurdir;
		if (gLocalPath.back() != '\\' && gLocalPath.back() != '/')
		{
			gLocalPath = gLocalPath + "\\";
		}
	}

	string cfgfn = gLocalPath + CONFIG_FILENAME;
	string pluginpath = gLocalPath + "Plugin\\";
	if (_access(pluginpath.c_str(), 0) || _access(cfgfn.c_str(), 0))
	{
		int len = GetModuleFileNameA(0, szcurdir, MAX_PATH);
		for (int i = len - 1; i >= 0; i--)
		{
			if (szcurdir[i] == '\\' || szcurdir[i] == '/')
			{
				szcurdir[i + 1] = 0;
				break;
			}
		}
		gLocalPath = szcurdir;
	}

	if (gLocalPath.back() != '\\' && gLocalPath.back() != '/')
	{
		gLocalPath = gLocalPath + "\\";
	}
	return gLocalPath;
}

string Public::getPluginPath() {
	if (gLocalPath == "")
	{
		gLocalPath = getpath();
	}
	return gLocalPath + "Plugin\\";
}

string Public::getPluginPathWithoutSlash() {
	if (gLocalPath == "")
	{
		gLocalPath = getpath();
	}
	return gLocalPath + "Plugin";
}

//why error here?
//filename = "D:\\vsproject\\attacker_thread\\attacker\\Plugin\\jy20200303"
string Public::getUserPluginPath(string username) {
	if (gLocalPath == "")
	{
		gLocalPath = getpath();
	}

	char path[MAX_PATH];
	lstrcpyA(path, gLocalPath.c_str());
	lstrcatA(path, "plugin\\");
	lstrcatA(path, username.c_str());
	lstrcatA(path, "\\");
	return string(path);

	//return gLocalPath + "Plugin\\" +  username + "\\";
}



string Public::getDefaultUserPluginPath() {
	if (gLocalPath == "")
	{
		gLocalPath = getpath();
	}
	return gLocalPath + "Plugin\\" + string(G_USERNAME) + "\\";
}



string Public::getUserUrl(string username, string filename) {

	return string("/") + username + "/" + filename;
}



string Public::getLogPath() {
	if (gLocalPath == "")
	{
		gLocalPath = getpath();
	}
	return gLocalPath + "output\\";
}


DWORD Public::log(const char* format, ...)
{
	CHAR szbuf[4096];

	va_list   pArgList;

	va_start(pArgList, format);

	int nByteWrite = vsprintf_s(szbuf, sizeof(szbuf) / sizeof(CHAR), format, pArgList);

	va_end(pArgList);

	OutputDebugStringA(szbuf);

	string fn = getLogPath() + ATTACK_LOG_FILENAME;
	int iRet = 0;
	FILE* fpFile = 0;
	iRet = fopen_s(&fpFile, fn.c_str(), "ab+");
	if (fpFile > 0)
	{
		int writelen = nByteWrite;
		iRet = fwrite(szbuf, 1, writelen, fpFile);
		fclose(fpFile);
		if (iRet != writelen)
		{
			printf("write file:%s error:%u\n", fn.c_str(), GetLastError());
			return FALSE;
		}
		return TRUE;
	}
	else
	{
		printf("file:%s open error:%u\n", fn.c_str(), GetLastError());
		return FALSE;
	}
	return FALSE;
}

int Public::WriteLogFile(const char* szFileName, unsigned char* strBuffer, int iCounter, const char* tag)
{
	if (iCounter <= 0)
	{
		return -1;
	}

	string fn = getLogPath() + szFileName;
	int iRet = 0;
	FILE* fpFile = 0;
	iRet = fopen_s(&fpFile, fn.c_str(), "ab+");
	if (fpFile > 0)
	{
		int taglen = lstrlenA(tag);
		if (taglen > 0)
		{
			iRet = fwrite(tag, 1, lstrlenA(tag), fpFile);
		}

		iRet = fwrite(strBuffer, 1, iCounter, fpFile);
		fclose(fpFile);
		if (iRet != iCounter)
		{
			printf("write file:%s error:%u\n", fn.c_str(), GetLastError());
			return FALSE;
		}
		return TRUE;
	}
	else
	{
		printf("file:%s open error:%u\n", fn.c_str(), GetLastError());
		return FALSE;
	}
	return FALSE;
}


DWORD Public::WriteLogFile(const char* pFileName, const char* pData, int datasize)
{
	return Public::WriteLogFile(pFileName, (unsigned char*)pData, datasize, "");
}





DWORD Public::WriteLogFile(const char* pData)
{
	string fn = getLogPath() + ATTACK_LOG_FILENAME;
	int iRet = 0;
	FILE* fpFile = 0;
	iRet = fopen_s(&fpFile, fn.c_str(), "ab+");
	if (fpFile > 0)
	{
		int writelen = lstrlenA(pData);
		iRet = fwrite(pData, 1, writelen, fpFile);
		fclose(fpFile);
		if (iRet != writelen)
		{
			printf("write file:%s error:%u\n", fn.c_str(), GetLastError());
			return FALSE;
		}
		return TRUE;
	}
	else
	{
		printf("file:%s open error:%u\n", fn.c_str(), GetLastError());
		return FALSE;
	}
	return FALSE;
}

DWORD Public::recordipv6user(unsigned char* ipv6, string app)
{
	char log[1024];
	string time = Public::getDateTime();
	wsprintfA(log, "attack user:%s,app:%s,time:%s\r\n", HttpUtils::getIPv6str(ipv6).c_str(), app.c_str(), time.c_str());
	WriteLogFile((const char*)log);
	return TRUE;
}

DWORD Public::recorduser(unsigned long ip, string app)
{
	char log[1024];
	string time = Public::getDateTime();
	wsprintfA(log, "attack user:%s,app:%s,time:%s\r\n", HttpUtils::getIPstr(ip).c_str(), app.c_str(), time.c_str());
	WriteLogFile((const char*)log);
	return TRUE;
}


int Public::removespace(char* src, char* dst)
{
	int len = strlen(src);
	int i = 0, j = 0;
	for (; i < len; i++) {
		if (src[i] == ' ' || src[i] == 0x9) {
			continue;
		}
		else {
			dst[j] = src[i];
			j++;
		}
	}
	*(dst + j) = 0;
	return j;
}




DWORD Public::checkInstanceExist()
{
	HANDLE hMutex = CreateMutexA(NULL, TRUE, ATTACKER_MUTEX_NAME);
	DWORD dwRet = GetLastError();
	if (hMutex)
	{
		if (ERROR_ALREADY_EXISTS == dwRet)
		{
			CloseHandle(hMutex);
			return FALSE;
		}
		else
		{
			return (DWORD)hMutex;
		}
	}
	else {
		printf("CreateMutexA error\r\n");
		return FALSE;
	}
}




int Public::getNameAndPathFromUrl(string url, string& filename, string& path) {
	int ret = 0;

	int pos = url.find_last_of("/");
	if (pos >= 0)
	{
		filename = url.substr(pos + 1);

		path = url.substr(0, pos);

		return TRUE;
	}

	return FALSE;
}



int Public::isipstr(const char* str) {
	int len = lstrlenA(str);
	for (int i = 0; i < len; i++)
	{
		if ((str[i] >= '0' && str[i] <= '9') || (str[i] == '.'))
		{
			continue;
		}
		else {
			return FALSE;
		}
	}

	return TRUE;
}



string Public::getNameFromFullPath(string fullpath) {
	int pos = fullpath.find_last_of("\\");
	if (pos != string::npos)
	{
		return fullpath.substr(pos + 1);
	}

	return fullpath;
}


string Public::getPathFromFullPath(string fullpath) {
	int pos = fullpath.find_last_of("\\");
	if (pos != string::npos)
	{
		return fullpath.substr(0, pos + 1);
	}

	return fullpath;
}


/*
10.0.0.0到10.255.255.255是私有地址
127.0.0.0到127.255.255.255是保留地址
172.16.0.0到172.31.255.255是私有地址
169.254.0.0到169.254.255.255是保留地址
192.168.0.0到192.168.255.255是私有地址
*/

int Public::isPrivateIPAddress(string ip) {
	if (memcmp(ip.c_str(), "10.", 3) == 0 || memcmp(ip.c_str(), "127.", 4) == 0 ||
		memcmp(ip.c_str(), "172.16.", 7) == 0 || memcmp(ip.c_str(), "169.254.", 8) == 0 ||
		memcmp(ip.c_str(), "192.168.", 8) == 0)
	{
		return TRUE;
	}

	return FALSE;
}

int Public::isPrivateIPAddress(DWORD dwip) {
	DWORD ip = ntohl(dwip);
	if ((ip >= 0x0a000000 && ip <= 0x0affffff) || (ip >= 0x7f000000 && ip <= 0x7fffffff) ||
		(ip >= 0xac100000 && ip <= 0xac1fffff) || (ip >= 0xa9fe0000 && ip <= 0xa9feffff) ||
		(ip >= 0xc0a80000 && ip <= 0xc0a8ffff))
	{
		return TRUE;
	}

	return FALSE;
}