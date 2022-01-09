#include <windows.h>
#include <winsock2.H>
#include <Iptypes.h >
#include <iphlpapi.h>
#include <string>
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "NetCardInfo.h"

#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")

#pragma comment(lib,"./lib\\wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std;

#define WINPCAP_MAX_PACKET_SIZE 0x10000
#define WINPCAP_MAX_BUFFER_SIZE 0x400000
#define WINPCAP_NETCARD_NAME_PREFIX			"\\Device\\NPF_"



//参数是从函数pcap_loop()传递过来的
//回调函数必须是全局函数或静态函数
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if (header->caplen != header->len || header->caplen >= WINPCAP_MAX_PACKET_SIZE || header->caplen <= 0)
	{
		printf("packet_handler packet len:%u error\r\n", header->caplen);
		return;
	}
	
	int ret = pcap_sendpacket((pcap_t*)param, pkt_data, header->caplen);
	if (ret )
	{
		printf("packet_handler send packet error\r\n");
	}
}



int main() {

	//MakeSureDirectoryPathExists("d:\\testtest");

	int ret = 0;
	WSADATA wsa = { 0 };
	ret = WSAStartup(0x0202, &wsa);

	unsigned long ip = 0;
	unsigned char mac[6] = { 0 };
	unsigned long gatewayip = 0;
	unsigned long netmask = 0;
	string devname = NetCardInfo::selectWeapon(&ip, &netmask, &gatewayip, mac);
	string pcapdevname = string(WINPCAP_NETCARD_NAME_PREFIX) + devname;

	char ebuf[PCAP_ERRBUF_SIZE];
	//"\\Device\\NPF_{DA2E76C1-BC02-49F0-BB36-D71FD590E80E}"
	pcap_t * pcaptsend = pcap_open_live(pcapdevname.c_str(), WINPCAP_MAX_PACKET_SIZE, 1, 1000, ebuf);
	if (pcaptsend == NULL)
	{
		printf("pcap_open_live error\n");
		getchar();
		return 0;
	}

	ret = pcap_setbuff(pcaptsend, WINPCAP_MAX_BUFFER_SIZE);	
	if (ret == -1)
	{
		printf("pcap_setbuff size:%d error\n", WINPCAP_MAX_BUFFER_SIZE);
		getchar();
		return FALSE;
	}

	string filename = "dnsattack.pcap";

	pcap_t *pcaptf = pcap_open_offline(filename.c_str(), ebuf);
	if (pcaptf <= 0)
	{
		printf("pcap_open_offline error\n");
		getchar();
		return 0;
	}

	//第二个是指定捕获的数据包个数,如果为-1则无限循环捕获
	ret = pcap_loop(pcaptf, 0, packet_handler, (unsigned char*)pcaptsend);

	WSACleanup();

	pcap_close(pcaptsend);
	pcap_close(pcaptf);


	printf("send pcap file ok\r\n");
	getchar();

	return 0;
}