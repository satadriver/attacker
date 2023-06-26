#include <windows.h>
#include <winsock2.H>
#include <Iptypes.h >
#include <iphlpapi.h>
#include <string>
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <dbghelp.h>
#include <conio.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "NetCardInfo.h"

#include "sendpack.h"



#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"./lib\\wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std;

int g_packnum = 0;


//第一个参数argument是从函数pcap_loop()传递过来的。注意：这里的参数就是指 pcap_loop中的最后一个参数
//第二个参数pcap_pkthdr 表示捕获到的数据包基本信息, 包括时间, 长度等信息.
//第三个参数pcap_content表示捕获到的数据包的内容
//另外 : 回调函数必须是全局函数或静态函数
static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if ((header->caplen != header->len) || (header->caplen >= WINPCAP_MAX_PACKET_SIZE) || (header->caplen <= 0))
	{
		printf("packet_handler packet len:%u or caplen:%d error\r\n", header->len, header->caplen);
		return;
	}

	int ret = pcap_sendpacket((pcap_t*)param, pkt_data, header->caplen);
	if (ret)
	{
		printf("packet_handler send packet number:%u length:%d error\r\n", g_packnum, header->len);
	}
	g_packnum++;
}



int main(int argc, char** argv) {

	if (argc < 2)
	{
		printf("caution!\r\nusage: sendpack.exe test.pcap\r\n");
		return TRUE;
	}

	string filename = argv[1];
	HANDLE hf = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		printf("pcap file:%s not found!\r\n", filename.c_str());
		return FALSE;
	}
	else {
		CloseHandle(hf);
	}

	int ret = 0;
	WSADATA wsa = { 0 };
	ret = WSAStartup(0x0202, &wsa);

	unsigned long ip = 0;
	unsigned char mac[MAC_ADDRESS_SIZE] = { 0 };
	unsigned long gatewayip = 0;
	unsigned long netmask = 0;
	string devname = NetCardInfo::selectNetcard(&ip, &netmask, &gatewayip, mac);

	string pcapdevname = string(WINPCAP_NETCARD_NAME_PREFIX) + devname;

	char ebuf[PCAP_ERRBUF_SIZE] = { 0 };
	// dev name must be such as "\\Device\\NPF_{DA2E76C1-BC02-49F0-BB36-D71FD590E80E}"

	/*
device是指定要打开的网络设备的字符串; 在具有2.2或更高版本内核的Linux系统上，可以使用“any”或NULL的设备参数来捕获来自所有接口的数据包。

snaplen指定要捕获的最大字节数。如果该值小于捕获的数据包的大小，则该数据包的第一个snaplen字节将被捕获并作为数据包数据提供。
在大多数（如果不是全部）网络中，值65535应该足以捕获数据包中可用的所有数据。

promisc指定是否将接口置于混杂模式。（注意，即使这个参数是假的，接口也可能在混杂模式下出于某些其他原因。）现在，这不适用于“任何”设备;
如果提供了“any”或NULL的参数，则将忽略promisc标志。

to_ms指定读取超时（以毫秒为单位）。读取超时用于安排在看到数据包时读取不一定立即返回，但是在一次操作中，
等待一段时间才能允许更多数据包到达并从操作系统内核读取多个数据包。
并非所有平台都支持读取超时; 在没有的平台上，读取超时被忽略。对于支持读取超时的平台，
to_ms的零值将导致读取永远等待，以允许足够的数据包到达，没有超时。

errbuf用于返回错误或警告文本。当pcap_open_live（）失败并返回NULL时，它将被设置为错误文本。
当pcap_open_live（）成功时，errbuf也可能设置为警告文本; 为了检测这种情况，
调用者在调用pcap_open_live（）之前应该在errbuf中存储一个零长度的字符串，并且如果errbuf不再是零长度字符串，则向用户显示警告。

*/
	pcap_t* pcaptsend = pcap_open_live(pcapdevname.c_str(), WINPCAP_MAX_PACKET_SIZE, PCAP_OPENFLAG_PROMISCUOUS, 1000, ebuf);
	if (pcaptsend == NULL)
	{
		printf("pcap_open_live:%s error:%s\r\n,or winpcap not installed!", pcapdevname.c_str(), ebuf);
		_getch();
		return 0;
	}

	if (ebuf[0])
	{
		printf("%s\r\n", ebuf);
	}

	ret = pcap_setbuff(pcaptsend, WINPCAP_MAX_BUFFER_SIZE);
	if (ret == -1)
	{
		printf("pcap_setbuff size:%d error:%s\n", WINPCAP_MAX_BUFFER_SIZE, ebuf);
		_getch();
		return FALSE;
	}

	if (ebuf[0])
	{
		printf("%s\r\n", ebuf);
	}

	pcap_t* pcaptf = pcap_open_offline(filename.c_str(), ebuf);
	if (pcaptf <= 0)
	{
		printf("pcap_open_offline:%s error:%s\r\n", filename.c_str(), ebuf);
		_getch();
		return 0;
	}

	if (ebuf[0])
	{
		printf("%s\r\n", ebuf);
	}

	//第一个参数是winpcap的句柄；
	//第二个是指定捕获的数据包个数, 如果为 -1则无限循环捕获, 除非出现错误则停止抓包；如果为0，表示处理所有数据包，读取到EOF时结束；
	//第三个参数是回调函数
	//第四个参数user是留给用户使用的；

	g_packnum = 0;

	ret = pcap_loop(pcaptf, 0, packet_handler, (unsigned char*)pcaptsend);

	if (ebuf[0])
	{
		printf("%s\r\n", ebuf);
	}

	pcap_close(pcaptsend);

	pcap_close(pcaptf);

	WSACleanup();

	printf("send pcap file ok\r\n");

	_getch();

	return 0;
}