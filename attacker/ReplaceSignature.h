


#ifndef BASEDATA_H_H_H
#define BASEDATA_H_H_H


#include "ReplaceNetFile.h"
#include "ReplacePacket.h"
#include "Packet.h"

using namespace std;



class ReplaceSignature:public ReplaceNetFile {
public:
	ReplaceSignature(){};
	~ReplaceSignature(){};

	char * m_lpfield;
	int m_fieldlen;
	
	int m_iRespSize;
	char m_lpResp[MAX_RESPONSE_HEADER_SIZE];

	int getField(char * flag,char * end,const char * lpbuf);

	int getField(char * flag, char * end, char * secend,const char * lpbuf);

	int setField(char * flag,char * lpdstbuf);

	int sendRespData(pcap_t * pcapT,const char * lppacket,int packetsize,char * ip,int type,LPPPPOEHEADER pppoe);


	int setRespParams(char * flag, char * end, char *lpresp);
};


#endif