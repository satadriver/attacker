#pragma once

#ifndef SERVERPROC_H_H_H
#define SERVERPROC_H_H_H

#include <windows.h>
#include "sslPublic.h"


// typedef struct {
// 	SOCKET sclient;
// 	sockaddr_in saclient;
// }CONNECTIONPARAM, *LPCONNECTIONPARAM;



class PluginServer {
public:
	static int SendPluginFile(const char * lpfn, LPHTTPPROXYPARAM lpparam, char * szHttpRespHdrFormat,int flag);
	static int PluginServerProc(LPHTTPPROXYPARAM lpparam,char * lpdata,int size);
	static int SendPluginFile(const char * lpfn, LPHTTPPROXYPARAM lpparam, const char * szHttpRespHdrFormat, int start, int end, int flag);

	static int PluginServerProc(LPSSLPROXYPARAM lpparam, char * lpdata, int size);
	static int SendPluginFile(const char * lpfn,LPSSLPROXYPARAM lpparam,const char * format, int flag);
	static int SendPluginFile(const char * lpfn, LPSSLPROXYPARAM lpparam, const char * szHttpRespHdrFormat, int start, int end, int flag);

	static char * getContentType(string url);
	static char * getPartialContentType(string url);
};


#endif
