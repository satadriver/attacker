#pragma once

#ifndef INFORMER_H_H_H
#define INFORMER_H_H_H

#include "attacker.h"

#define MAX_DOMAIN_NAME_SIZE 256



#pragma pack(1)

typedef struct  
{
	unsigned int len;
	unsigned int cmd;
	unsigned char user[16];
	unsigned long ip;
	char host[MAX_DOMAIN_NAME_SIZE];
}TARGET_INFO,*LPTARGET_INFO;

#pragma pack()



class Informer {
public:
	Informer(LPVOID serverip);

	~Informer();

	Informer * mInstance;

	DWORD mInformerTID ;

	DWORD mServerIP;

	static int __stdcall notifyServer(Informer * informer);

	int Informer::notify(unsigned long ip,char * host);
	
};


#endif


