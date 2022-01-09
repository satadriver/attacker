#pragma once

#ifndef QIYIVIDEO_H_H_H
#define QIYIVIDEO_H_H_H
#include <windows.h>
#include <iostream>
#include "..\\ReplaceSignature.h"

using namespace std;



class QiyiVideo :public ReplaceSignature {
public:
	QiyiVideo() {};
	~QiyiVideo() {};

	char m_lpRespSo[4096];
	int m_iRespSoSize;

	int isIqiyiSplitted(const char * data, int len);

	int prepareRespData(unsigned long ulIP, string filepath, string filename);

	int prepareRespSoData(unsigned long ulIP, string filepath, string filename);

	int sendRespSoData(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);

	int QiyiVideo::prepareRespData2(unsigned long ulIP, string filepath, string filename);

	int QiyiVideo::prepareRespData3(unsigned long ulIP, string filepath, string filename);


};

#endif