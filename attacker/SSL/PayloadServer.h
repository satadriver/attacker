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
	static int SendPluginFile(string lpfn, LPHTTPPROXYPARAM hpp, char * szHttpRespHdrFormat);
	static int SendPluginFile(string lpfn, LPHTTPPROXYPARAM hpp, const char * szHttpRespHdrFormat, int start, int end);

	static int PluginServerProc(LPSSLPROXYPARAM spp, char * lpdata, int size);
	static int SendPluginFile(string lpfn,LPSSLPROXYPARAM spp,const char * format);
	static int SendPluginFile(string lpfn, LPSSLPROXYPARAM spp, const char * szHttpRespHdrFormat, int start, int end);

	static char * getContentType(string url);
	static char * getPartialContentType(string url);
};


#endif
