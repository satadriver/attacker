#include "gateway.h"
#include "../winpcap.h"
#include "../packet.h"
#include <algorithm>
#include "../ssl/sslpublic.h"
#include "../HttpUtils.h"
#include "../Utils/checksum.h"


Gateway::Gateway(pcap_t * pcapt,DWORD serverip,DWORD localip,unsigned char * localmac) {
	if (mInstance)
	{
		return;
	}
	mInstance = this;

	mCnt = 0;

	mPcapt = pcapt;
	mServerIP = serverip;
	mLocalIP = localip;
	memcpy(mLocalMac, localmac, 6);
}



Gateway::~Gateway() {
	mInstance = NULL;
}



int Gateway::sendServerUsername(Gateway * instance) {

	int ret = 0;

	GATEWAYPARAM param = instance->getGatewayParam();

	LPGATEWAYPARAM p = &param;

	int usernamelen = lstrlenA(G_USERNAME);

	char data[1024] = { 0 };

	char * nextpack = data;

	int totalsize = 0;

	LPMACHEADER mac = (LPMACHEADER)nextpack;
	memcpy(mac, &p->mac, sizeof(MACHEADER));

	nextpack += sizeof(MACHEADER);
	totalsize += sizeof(MACHEADER);

	if (p->hdr8021_1.type)
	{
		LPHEADER8021Q p8021_1 = (LPHEADER8021Q)((char*)data + sizeof(MACHEADER));
		memcpy((char*)p8021_1, (char*)&p->hdr8021_1, sizeof(HEADER8021Q));

		if (p->hdr8021_2.type)
		{
			LPHEADER8021Q p8021_2 = (LPHEADER8021Q)((char*)p8021_1 + sizeof(HEADER8021Q));
			memcpy((char*)p8021_2, (char*)&p->hdr8021_2, sizeof(HEADER8021Q));

			nextpack = nextpack + sizeof(HEADER8021Q)*2;

			totalsize += sizeof(HEADER8021Q)*2;
		}
		else {
			nextpack = nextpack + sizeof(HEADER8021Q);

			totalsize += sizeof(HEADER8021Q);
		}
	}
	
	if (p->pppoe.protocol)
	{
		LPPPPOEHEADER pppoe = (LPPPPOEHEADER)(nextpack);
		memcpy((char*)pppoe, (char*)&p->pppoe, sizeof(PPPOEHEADER));

		pppoe->len = ntohs(sizeof(IPHEADER) + sizeof(UDPHEADER) + usernamelen + 2);

		nextpack = nextpack + sizeof(PPPOEHEADER);

		totalsize += sizeof(PPPOEHEADER);
	}

	LPIPHEADER piphdr = (LPIPHEADER)nextpack;
	memcpy(nextpack, (char*)&p->ip, sizeof(IPHEADER));
	piphdr->DstIP = instance->mServerIP;
	piphdr->HeaderSize = 5;
	piphdr->Protocol = IPPROTO_UDP;
	piphdr->TimeToLive = 0x7f;
	piphdr->PacketSize = ntohs(sizeof(IPHEADER) + sizeof(UDPHEADER) + usernamelen);
	piphdr->flag = 0;
	piphdr->HeaderChksum = 0;
	piphdr->HeaderChksum = Checksum::checksum((WORD*)piphdr, sizeof(IPHEADER));
	
	totalsize += sizeof(IPHEADER);
	
	LPUDPHEADER pudp = (LPUDPHEADER)((char*)piphdr + sizeof(IPHEADER));
	pudp->DstPort = ntohs(SERVER_UDP_NOTIFY_PORT);
	pudp->SrcPort = ntohs(SERVER_UDP_NOTIFY_PORT);
	pudp->PacketSize = ntohs(usernamelen + sizeof(UDPHEADER));
	totalsize += sizeof(UDPHEADER);

	lstrcpyA(data + totalsize, G_USERNAME);
	totalsize += usernamelen;
	*(DWORD*)(data + totalsize) = 0;

	pudp->PacketChksum = 0;
	pudp->PacketChksum = Checksum::subPackChecksum((char*)pudp, usernamelen + sizeof(UDPHEADER), piphdr->SrcIP, piphdr->DstIP, IPPROTO_UDP);

	int packsize = totalsize;
// 	if (packsize < 60)
// 	{
// 		packsize = 60;
// 	}

	while (1)
	{
		ret = pcap_sendpacket(instance->mPcapt, (unsigned char*)data, packsize);
		Sleep(60000);
	}
	
	return ret;
}



int getIPHdr(LPMACHEADER mac,LPHEADER8021Q & p8021q_1,LPHEADER8021Q & p8021q_2, LPPPPOEHEADER & pppoe, LPIPHEADER &ip, LPIPV6HEADER &ipv6) {

	char * nexthdr = (char*)mac + sizeof(MACHEADER);
	int nextprotocol = mac->Protocol;

	if (nextprotocol == 0x0081)
	{
		p8021q_1 = (LPHEADER8021Q)nexthdr;

		if (p8021q_1->type == 0x0081)
		{
			p8021q_2 = LPHEADER8021Q((char*)p8021q_1 + sizeof(HEADER8021Q));

			nexthdr = (char*)p8021q_2 + (sizeof(HEADER8021Q));

			nextprotocol = p8021q_2->type;
		}
		else {
			nexthdr = (char*)p8021q_1 + sizeof(HEADER8021Q);

			nextprotocol = p8021q_1->type;
		}
	}
	else if (nextprotocol == 0x9899 || nextprotocol == 0xa788 || nextprotocol == 0xcc88)
	{
		return 0;
	}

	//assume ip hdr is after pppoe
	//0x8863（Discovery阶段或拆链阶段）或者0x8864（Session阶段）
	if (nextprotocol == 0x6488)
	{
		//0×C021 LCP数据报文
		//0×8021 NCP数据报文
		//0×0021 IP数据报文

		pppoe = (LPPPPOEHEADER)nexthdr;
		nextprotocol = pppoe->protocol;

		if (nextprotocol == 0x2100)
		{
			nexthdr = (char*)pppoe + sizeof(PPPOEHEADER);

			ip = (LPIPHEADER)nexthdr;

			return 1;
		}
		else if (nextprotocol == 0x5700 || nextprotocol == 0x5780) //ipv6
		{
			nexthdr = (char*)pppoe + sizeof(PPPOEHEADER);

			ipv6 = (LPIPV6HEADER)nexthdr;

			return 2;
		}
		else if (nextprotocol == 0x21c0 || nextprotocol == 0x0101 || nextprotocol == 0x23c0 || nextprotocol == 0x22c0 || nextprotocol == 0x2180)
		{
			return 0;
		}
		else {
			return -1;
		}
	}
	else if (nextprotocol == 0x0008)
	{
		ip = (LPIPHEADER)nexthdr;
		return 1;
	}
	else if (nextprotocol == 0xdd86)
	{
		ipv6 = (LPIPV6HEADER)nexthdr;

		return 2;
	}
	//0x2700 IEEE 802.3
	else if (nextprotocol == 0x0608 || nextprotocol == 0x6388 || nextprotocol == 0x2700)
	{
		return 0;
	}
	else {
		return -1;
	}
}




bool cmp(pair<string, GATEWAYPARAM> a, pair<string, GATEWAYPARAM> b) {
	return a.second.cnt > b.second.cnt;
}





GATEWAYPARAM Gateway::getGatewayParam() {
	vector< pair<string, GATEWAYPARAM> > vec;

	vec.clear();

	for (unordered_map<string, GATEWAYPARAM>::iterator it = mGatewayMap.begin(); it != mGatewayMap.end(); it++) {
		vec.push_back(pair<string, GATEWAYPARAM>(it->first, it->second));
	}

	sort(vec.begin(), vec.end(), cmp);


	GATEWAYPARAM result = vec.at(0).second;

	char szout[1024];
	string srcip = HttpUtils::getIPstr(result.ip.SrcIP);
	string dstip = HttpUtils::getIPstr(result.ip.DstIP);

	string srcmac = HttpUtils::getmac(result.mac.SrcMAC);
	string dstmac = HttpUtils::getmac(result.mac.DstMAC);
	wsprintfA(szout, "gateway mac:%s,packet count:%d,mac count:%d,srcmac:%s,srcip:%s,dstmac:%s,dstip:%s\r\n",
		vec.at(0).first.c_str(), result.cnt,mCnt, srcmac.c_str(), srcip.c_str(), dstmac.c_str(), dstip.c_str());
	printf(szout);

	return vec.at(0).second;
}



int Gateway::getGateWay() {
	pcap_pkthdr *	pHeader = 0;
	const char * pData = 0;

	DWORD totalcnt = 0;

	int iret = 0;
	while (TRUE)
	{
		iret = pcap_next_ex(mPcapt, &pHeader, (const unsigned char**)&pData);
		int iCapLen = pHeader->len;
		if (iret == 0)
		{
			continue;
		}
		else if (iret < 0)
		{
			printf("pcap_next_ex error:%s,return value:%d\r\n", pcap_geterr(mPcapt), iret);
			continue;
		}
		else if (iCapLen >= WINPCAP_MAX_PACKET_SIZE || iCapLen <= 0)
		{
			printf("pcap_next_ex error:%s,packet caplen:%u or len:%u error\r\n", pcap_geterr(mPcapt), pHeader->caplen, pHeader->len);
			continue;
		}

		*((char*)pData + iCapLen) = 0;


		LPPPPOEHEADER pppoe = 0;
		LPIPHEADER pIPV4 = 0;
		LPIPV6HEADER pIPV6 = 0;
		LPMACHEADER pMac = (LPMACHEADER)pData;
		LPHEADER8021Q p8021_1 = 0;
		LPHEADER8021Q p8021_2 = 0;
		int iptype = getIPHdr(pMac, p8021_1,p8021_2, pppoe, pIPV4, pIPV6);
		if (iptype != 1 )
		{
			continue;
		}

		int protocol = 0;
		if (pIPV4)
		{
			protocol = pIPV4->Protocol;
		}else if (pIPV6)
		{
			protocol = pIPV6->NextPacket;
		}

		if (protocol == IPPROTO_UDP || protocol == IPPROTO_TCP)
		{
			unsigned short usDport = 0;
			if (protocol == IPPROTO_UDP)
			{
				LPUDPHEADER pUdpHdr = (LPUDPHEADER)((char*)pIPV4 + (pIPV4->HeaderSize << 2));
				usDport = ntohs(pUdpHdr->DstPort);
			}else if (protocol == IPPROTO_TCP)
			{
				LPTCPHEADER ptcp = (LPTCPHEADER)((char*)pIPV4 + (pIPV4->HeaderSize << 2));
				usDport = ntohs(ptcp->DstPort);
			}


			if (usDport == DNS_PORT || usDport == HTTP_PORT || usDport == SSL_PORT)
			{
				string dmackey = HttpUtils::getmac(pMac->DstMAC);

				unordered_map <string, GATEWAYPARAM>::iterator it;

				it = mGatewayMap.find(dmackey);
				if (it == mGatewayMap.end())
				{
					GATEWAYPARAM param = { 0 };
					param.cnt = 1;
					memcpy((char*)&param.mac, (char*)pMac, sizeof(MACHEADER));

					if (p8021_1)
					{
						memcpy((char*)&param.hdr8021_1, (char*)p8021_1, sizeof(HEADER8021Q));
					}

					if (p8021_2)
					{
						memcpy((char*)&param.hdr8021_2, (char*)p8021_2, sizeof(HEADER8021Q));
					}

					if (pppoe)
					{
						memcpy(&param.pppoe, pppoe, sizeof(PPPOEHEADER));
					}

					memcpy((char*)&param.ip, (char*)pIPV4, sizeof(IPHEADER));

					mGatewayMap.insert(pair<string, GATEWAYPARAM>(dmackey, param));
				}
				else {
					it->second.cnt++;
				}

				mCnt++;
				
#ifdef _DEBUG
				if (mCnt >= 1 && mGatewayMap.size() >= 1)

#else
				if (mCnt >= 1 && mGatewayMap.size() >= 1)
#endif
				{
					printf("\n");
					CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)sendServerUsername, this, 0, 0));
					return TRUE;
				}
			}
		}

		totalcnt++;
		if (totalcnt > 0x10000)
		{
			break;
		}
		printf("get packet total:%u,target count:%u\r", totalcnt,mCnt);
	}
	return FALSE;
}