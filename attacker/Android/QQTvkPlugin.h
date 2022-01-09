

#ifndef QQTVKPLUGIN_H_H_H
#define QQTVKPLUGIN_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"





class QQTvkPlugin :public ReplaceSignature {
public:
	QQTvkPlugin() {};
	~QQTvkPlugin() {};
	int prepareRespData(unsigned long ulIP, string filepath, string filename);

	int SetSdkVersion(char * szsdkver, char * lphttphdr);
};

#endif