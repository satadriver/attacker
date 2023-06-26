

#include "winpcap.h"


#pragma comment(lib,"..\\attacker\\lib\\wpcap.lib")
//#pragma comment(lib,"..\\attacker\\lib\\ssleay32.lib")
//#pragma comment(lib,"..\\attacker\\lib\\libeay32.lib")

using namespace std;


pcap_t * Winpcap::init(string devname, int delay, unsigned long netmask) {
	int ret = 0;
	char		strPcapErrBuf[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_t * pcapt = pcap_open_live(devname.c_str(), WINPCAP_MAX_PACKET_SIZE, 1, delay, strPcapErrBuf);
	if (pcapt == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", devname.c_str());
		getchar();
		return 0;
	}

	ret = pcap_setbuff(pcapt, WINPCAP_MAX_BUFFER_SIZE);	//the limit buffer size of capraw is 100M
	if (ret == -1)
	{
		printf("pcap_setbuff size:%d error\n", WINPCAP_MAX_BUFFER_SIZE);
		getchar();
		return FALSE;
	}

	//ret = pcap_setmode(pcapt, MODE_STAT);

	// 	bpf_program		stBpfp = { 0 };
	// 	ret = pcap_compile(pcapt, &stBpfp, PCAP_MAIN_FILTER, TRUE, netmask);
	// 	if (ret < 0)
	// 	{
	// 		fprintf(stderr, "数据包过滤条件语法设置失败,请检查过滤条件的语法设置\n");
	// 		getchar();
	// 		return FALSE;
	// 	}
	// 
	// 	ret = pcap_setfilter(pcapt, &stBpfp);
	// 	if (ret < 0)
	// 	{
	// 		fprintf(stderr, "数据包过滤条件设置失败\n");
	// 		getchar();
	// 		return FALSE;
	// 	}

	return pcapt;
}