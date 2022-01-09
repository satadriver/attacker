#include "kuaiya.h"
#include "PluginServer.h"
#include "../cipher/Code.h"
#include "../HttpUtils.h"


int KuaiyaUpdate::isKuaiya(const char * url, const char * host) {
	if (strstr(host, "api.dewmobile.net") ) {
		if (strstr(url, "/version/check"))
		{
			return TRUE;
		}
	}

	return FALSE;
}


int KuaiyaUpdate::replyKuaiyaUpdate(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lphttp) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %u\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string ver = "9.8.2";
	int vercode = 907;
	char * format = "{\"VERCODE\":%u,\"VERNAME\":\"%s (CN)\",\"AUTO\":true,\"URL\":\"http://%s/%s\",\"DESC\":\"1. update nignt\n2.patches\"}";
	
	char gbkdata[4096];
	int gbklen = sprintf(gbkdata, format, vercode, ver.c_str(), ip.c_str(), ANDROID_REPLACE_FILENAME);

// 	char utf8[4096];
// 	int utf8len = Code::gbk2utf8(gbkdata, gbklen, utf8, 4096);
// 	int retlen = sprintf(dstbuf, szHttpRespFormat, utf8len, utf8);

	int retlen = sprintf(dstbuf, szHttpRespFormat, gbklen, gbkdata);
	
	return retlen;
}


/*
GET api.dewmobile.net/v4/version/check HTTP/1.1
Cache-Control: no-cache
X-CM: hKPSP7SlI7oG
X-HasGP: 0
X-CHN: z0100034
X-ZV: 10154
X-VN: 5.8.2 (CN)
X-LAN: zh_CN
X-Network: WIFI
X-UUID: da2e8494-5233-3576-b532-5c3d75a6b468-857097
X-SDK: 22
X-AID: CnIlkmC9SBjmKlSl
X-PID: 0
X-IMSI: i/9
X-MDL: HUAWEI TAG-TL00
If-Modified-Since: Tue, 06 Aug 2019 11:07:07 GMT+00:00
X-CK: authToken=0812f07dd9bca726370f38866a6e34e0
X-Date: 1566552455563
X-VC: 307
X-UserId: 1765091620
X-MI: ljTnIKKSjlnTTnn
Host: api.dewmobile.net
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.9.0

HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Fri, 23 Aug 2019 09:27:33 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
Strict-Transport-Security: max-age=15724800; includeSubDomains
Content-Encoding: gzip

{"VERCODE":307,"VERNAME":"5.8.2 (CN)","AUTO":true,"URL":"http://downloadg.dewmobile.net/official/Kuaiya582.apk","DESC":"1. 新增夜间模式\n2. 修复问题，提升适配性"}
*/