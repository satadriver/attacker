#pragma once

#ifndef SERVERPROC_H_H_H
#define SERVERPROC_H_H_H

#include <windows.h>
#include "sslPublic.h"


// typedef struct {
// 	SOCKET sclient;
// 	sockaddr_in saclient;
// }CONNECTIONPARAM, *LPCONNECTIONPARAM;



class PayloadServer {
public:
	static int PluginServerProc(LPHTTPPROXYPARAM hpp, char* lpdata, int size);
	static int SendPluginFile(const char * lpfn, LPHTTPPROXYPARAM hpp, char * szHttpRespHdrFormat,int flag);
	static int SendPluginFile(const char * lpfn, LPHTTPPROXYPARAM hpp, const char * szHttpRespHdrFormat, int start, int end, int flag);

	static int PluginServerProc(LPSSLPROXYPARAM spp, char * lpdata, int size);
	static int SendPluginFile(const char * lpfn,LPSSLPROXYPARAM spp,const char * format, int flag);
	static int SendPluginFile(const char * lpfn, LPSSLPROXYPARAM spp, const char * szHttpRespHdrFormat, int start, int end, int flag);

	static char * getContentType(string url);
	static char * getPartialContentType(string url);
};


#endif
