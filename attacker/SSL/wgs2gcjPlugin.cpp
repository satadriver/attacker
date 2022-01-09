#include "wgs2gcjPlugin.h"
#include "PluginServer.h"


int Wgs2gcjPlugin::isWgs2gcj(const char * url, const char * host) {
	if (strstr(host, "oss-pub.aliyun-inc.com") == FALSE) {
		return FALSE;
	}

	if (strstr(url, "wgs2gcj.so"))
	{
		return TRUE;
	}

	return FALSE;
}

int Wgs2gcjPlugin::replyWgs2gcjPlugin(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, "libJni_wgs2gcj.so");
	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
	return ret;
}


/*
GET /sdkcoor/android/armeabi/libJni_wgs2gcj.so HTTP/1.1
Connection: close
csid: 5aaf181033ef46d3afdaa651d4560e24
RANGE: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: amap-api.cn-hangzhou.oss-pub.aliyun-inc.com
Accept-Encoding: gzip

HTTP/1.1 206 Partial Content
Date: Wed, 15 May 2019 02:52:40 GMT
Content-Type: application/octet-stream
Content-Length: 46396
Connection: close
x-oss-request-id: 5CDB7EF8CC2473C118B4F704
Content-Range: bytes 0-46395/46396
Accept-Ranges: bytes
ETag: "0273BB5BC2A88C53D899503FD536D31E"
Last-Modified: Wed, 06 Jan 2016 06:40:13 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 11137625807588296971
x-oss-storage-class: Standard
Content-MD5: AnO7W8KojFPYmVA/1TbTHg==
x-oss-server-time: 40
Server: Tengine/Aserver
EagleEye-TraceId: 0b838cf115578887601108018ea5e6
Timing-Allow-Origin: *
*/