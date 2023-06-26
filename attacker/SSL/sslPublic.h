
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

using namespace std;


#define SERVER_UDP_NOTIFY_PORT			65534

#define SSL_MAX_BLOCK_SIZE				0x4000

#define NETWORK_BUFFER_SIZE				0x4000

#define PROXY_THREAD_STACK_SIZE			(NETWORK_BUFFER_SIZE*4 + 0x10000)

#define CONNECTION_TIME_OUT				3000
#define SELECT_TIME_OUT					3000

//#define GENERAL_DOMAIN_NAME "baidu.com"
//#define GENERAL_DOMAIN_NAME "taobao.com"


#define SSL_PROXY_FILE			"ssl.dat"
//#define HTTP_PROXY_FILE			"http.dat"




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
CSR 是Certificate Signing Request的缩写，即证书签名请求，这不是证书，可以简单理解成公钥，生成证书时要把这个提交给权威的证书颁发机构。
CRT 即 certificate的缩写，即证书。
X.509 是一种证书格式.对X.509证书来说，认证者总是CA或由CA指定的人，一份X.509证书是一些标准字段的集合，
这些字段包含有关用户或设备及其相应公钥的信息。
X.509的证书文件，一般以.crt结尾，根据该文件的内容编码格式，可以分为以下二种格式：
PEM - Privacy Enhanced Mail,打开看文本格式,以"-----BEGIN..."开头, "-----END..."结尾,内容是BASE64编码.
Apache和*NIX服务器偏向于使用这种编码格式.
DER - Distinguished Encoding Rules,打开看是二进制格式,不可读.Java和Windows服务器偏向于使用这种编码格式
*/




//#define	PRIVATE_KEY_PWD		"sata19820521"					// 私钥的密码
//#define	CERT_FILE			"..\\key\\example.crt"			// 伪造的证书
//#define	KEY_FILE			"..\\key\\example.key"			// 伪造证书的私钥
//#define	CERT_FILE			"..\\key\\liujinguangscrt.crt"		// 伪造的证书
//#define	CERT_FILE			"..\\key\\server-cert.pem.crt"		// 伪造的证书
//#define	KEY_FILE			"..\\key\\server-key.pem"				// 伪造证书的私钥







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
	char				username[32];
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
}WORKERCONTROL, * LPWORKCONTROL;

#pragma pack()


extern unsigned char gLocalIPAddrV6[16];
extern DWORD		gLocalIPAddr;
extern string		gstrLocalIP;

extern DWORD		gServerIP;
extern string		gstrServerIP;

extern string		gLocalPath;
extern string		gOpensslPath;

extern WORKERCONTROL gWorkControl;


class SSLPublic {
public:

	SSLPublic(vector<string>list);
	~SSLPublic();

	SSLPublic* mInstance;

	static int SSLPublic::isTargetHost(string host);
	static int prepareCertChain(string certname);

	static int SSLPublic::freeSSLPort();
};



#endif