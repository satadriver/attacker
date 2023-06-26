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


//��һ������argument�ǴӺ���pcap_loop()���ݹ����ġ�ע�⣺����Ĳ�������ָ pcap_loop�е����һ������
//�ڶ�������pcap_pkthdr ��ʾ���񵽵����ݰ�������Ϣ, ����ʱ��, ���ȵ���Ϣ.
//����������pcap_content��ʾ���񵽵����ݰ�������
//���� : �ص�����������ȫ�ֺ�����̬����
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
device��ָ��Ҫ�򿪵������豸���ַ���; �ھ���2.2����߰汾�ں˵�Linuxϵͳ�ϣ�����ʹ�á�any����NULL���豸�����������������нӿڵ����ݰ���

snaplenָ��Ҫ���������ֽ����������ֵС�ڲ�������ݰ��Ĵ�С��������ݰ��ĵ�һ��snaplen�ֽڽ���������Ϊ���ݰ������ṩ��
�ڴ�������������ȫ���������У�ֵ65535Ӧ�����Բ������ݰ��п��õ��������ݡ�

promiscָ���Ƿ񽫽ӿ����ڻ���ģʽ����ע�⣬��ʹ��������Ǽٵģ��ӿ�Ҳ�����ڻ���ģʽ�³���ĳЩ����ԭ�򡣣����ڣ��ⲻ�����ڡ��κΡ��豸;
����ṩ�ˡ�any����NULL�Ĳ������򽫺���promisc��־��

to_msָ����ȡ��ʱ���Ժ���Ϊ��λ������ȡ��ʱ���ڰ����ڿ������ݰ�ʱ��ȡ��һ���������أ�������һ�β����У�
�ȴ�һ��ʱ���������������ݰ����ﲢ�Ӳ���ϵͳ�ں˶�ȡ������ݰ���
��������ƽ̨��֧�ֶ�ȡ��ʱ; ��û�е�ƽ̨�ϣ���ȡ��ʱ�����ԡ�����֧�ֶ�ȡ��ʱ��ƽ̨��
to_ms����ֵ�����¶�ȡ��Զ�ȴ����������㹻�����ݰ����û�г�ʱ��

errbuf���ڷ��ش���򾯸��ı�����pcap_open_live����ʧ�ܲ�����NULLʱ������������Ϊ�����ı���
��pcap_open_live�����ɹ�ʱ��errbufҲ��������Ϊ�����ı�; Ϊ�˼�����������
�������ڵ���pcap_open_live����֮ǰӦ����errbuf�д洢һ���㳤�ȵ��ַ������������errbuf�������㳤���ַ����������û���ʾ���档

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

	//��һ��������winpcap�ľ����
	//�ڶ�����ָ����������ݰ�����, ���Ϊ -1������ѭ������, ���ǳ��ִ�����ֹͣץ�������Ϊ0����ʾ�����������ݰ�����ȡ��EOFʱ������
	//�����������ǻص�����
	//���ĸ�����user�������û�ʹ�õģ�

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