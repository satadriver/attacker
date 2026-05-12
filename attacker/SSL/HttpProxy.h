#pragma once

#ifndef HTTPPXOXY_H_H_H
#define HTTPPXOXY_H_H_H

#include <windows.h>
#include "sslPublic.h"





class HttpProxy {
public:
	static int __stdcall HTTPProxy(LPMIM_THREAD_PARAMS param);

	static int HttpProxy::HttpProxyMain(LPHTTPPROXYPARAM pstHttpProxyParam);
};
#endif