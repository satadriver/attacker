
#pragma once

#ifndef SSLPUBLIC_H_H_H
#define SSLPUBLIC_H_H_H


#include <WinSock2.h>
#include <windows.h>
#include <iostream>
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"
#include "../Public.h"
#include <vector>
#include "attacker.h"



using namespace std;


#define SERVER_UDP_NOTIFY_PORT			65534

#define SSL_MAX_BLOCK_SIZE				0x4000

#define NETWORK_BUFFER_SIZE				0x4000

#define PROXY_THREAD_STACK_SIZE			(NETWORK_BUFFER_SIZE*64)

#define CONNECTION_TIME_OUT				30000
#define SELECT_TIME_OUT					30000


#define SSL_PROXY_FILE					"ssl.txt"
#define HTTP_PROXY_FILE					"http.txt"

#define ROOT_CERT_C			"US"
#define ROOT_CERT_ST		"California"
#define ROOT_CERT_L			"\"Los\\ Angeles\""
#define ROOT_CERT_O			"\"DigiCert\\ Inc\""
#define ROOT_CERT_OU		"www.digicert.com"	
#define ROOT_CERT_CN		"\"DigiCert\\ Global\\ Root\\ CA\""			
#define ROOT_CERT_E			"www.digicert.com"

/*
#define ROOT_CERT_C			"US"
#define ROOT_CERT_ST		"California"
#define ROOT_CERT_L			"\"Los\\ Angeles\""
#define ROOT_CERT_O			"\"VeriSign,\\ Inc.\""
//(c)\\ 2008\\ VeriSign,\\ Inc.\\ -\\ For\\ authorized\\ use\\ only\\ VeriSign\\ Trust\\ Network
#define ROOT_CERT_OU		"\"VeriSign\\ Trust\\ Network\""		//distingsih root cert
#define ROOT_CERT_CN		"\"VeriSign\\ Universal\\ Root\\ Certification\\ Authority\""			//
#define ROOT_CERT_E			"www.verisign.com"
*/

#define SUBCA_KEY_FILENAME	"httpssubca.key"
#define CA_KEY_FILENAME		"httpsca.key"
#define CA_CSR_FILENAME		"httpsca.csr"
#define CA_CRT_FILENAME		"httpsca.crt"
#define	PRIVATE_KEY_PWD		"0123456789"	
#define MAKE_KEY_LEN		1024

#define OUTPUT_PATH			"output"

#define CERT_PATH			"Certifications"
#define CA_CERT_PATH		"CertificateAuthority"
#define DIGICERTCA			"DigiCertCA.crt"


#define OPENSSLPATH_FILENAME	"opensslPath.cfg"
#define OPENSSLCONFIG_FILENAME	"openssl.cfg"

//#define DEBUG_MAKE_CERT_V1
//#define DEBUG_MAKE_CERT_V3
#define DEBUG_MAKE_CERT_V3_EXT



//certmgr.msc

/*
PEM - Privacy Enhanced Mail 文本格式 ,Apache和NgIX服务器偏向于使用这种编码格式.
DER - Distinguished Encoding Rules 二进制格式, Java和Windows服务器偏向于使用这种编码格式
*/



#define OPENSSL_CLEAR_PATH		1
#define ROOTCERT_IMPORT			2




#pragma pack(1)
typedef struct
{
	sockaddr_in			saToClient;
	int					sockToClient;
	sockaddr_in			saToServer;
	int					sockToServer;

	char				host[256];
	char				username[32];
	unsigned long		ulThreadID;
	unsigned short		usPort;

	time_t				timeclient;
	time_t				timeserver;
}HTTPPROXYPARAM, * LPHTTPPROXYPARAM;





typedef struct
{
	sockaddr_in			saToClient;
	int					sockToClient;
	sockaddr_in			saToServer;
	int					sockToServer;

	char				host[256];
	char				username[USERNAME_MAXLEN];
	unsigned long		ulThreadID;
	unsigned short		usPort;

	time_t				timeclient;
	time_t				timeserver;

	int					version;

	SSL* SSLToClient;
	SSL* SSLToServer;
	SSL_CTX* ctxToServer;
	SSL_CTX* ctxToClient;
}SSLPROXYPARAM, * LPSSLPROXYPARAM;


typedef struct
{
	unsigned int protocol;
	unsigned short length;
	unsigned char data[14];
}SSLUSERDEFDATA, * LPSSLUSERDEFDATA;


typedef struct
{
	HANDLE gHTTPEvent;
	HANDLE gSSLEvent;
	HANDLE gHTTPListenEvent;
	HANDLE gSSLListenEvent;
	LPHTTPPROXYPARAM gHTTPProxyParam;
	LPSSLPROXYPARAM gSSLProxyParam;
}MIM_THREAD_PARAMS, * LPMIM_THREAD_PARAMS;

#pragma pack()

extern unsigned char	gLocalMac[MAC_ADDRESS_SIZE];

extern unsigned char	gRouterMac[MAC_ADDRESS_SIZE];

extern DWORD			gRouterIP ;
extern DWORD			gDnsServer;
extern DWORD			gNetmask;

extern unsigned char	gLocalIPV6[16];
extern DWORD			gLocalIP;
extern string			gstrLocalIP;

extern DWORD			gServerIP;
extern string			gstrServerIP;

extern string			gstrNetIP ;
extern DWORD			gNetIP;

extern string			gLocalPath;
extern string			gOpensslPath;
extern string			gOpensslWinPath;
extern string			gOpensslRoot;

extern MIM_THREAD_PARAMS	g_thread_params;


class SSLPublic {
public:

	SSLPublic::SSLPublic(vector<string>hostlist, vector<string>targetlist);
	~SSLPublic();

	SSLPublic* mInstance;

	static int SSLPublic::isTargetHost(string host);
	static int prepareCertChain(string certname);

	static int SSLPublic::freeSSLPort();

	static int isAttackTargetHost(string host);
};



#endif