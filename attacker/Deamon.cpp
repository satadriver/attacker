
#include "Deamon.h"
#include "attacker.h"
#include "ssl/sslPublic.h"
#include <windows.h>
#include "Public.h"
#include "ssl/sslproxy.h"
#include "Include/openssl/conf.h"
#include "Include/openssl/engine.h"
#include "ssl/HttpAttack.h"
#include "ssl/SSLAttack.h"
#include "Public.h"
#include "Utils/Tools.h"

Deamon *gDeamon = 0;


Deamon::Deamon() {
	mInstance = this;
	gDeamon = this;

	LOOP_TIME = CONNECTION_TIME_OUT + 60000;
	gOverTime = LOOP_TIME /1000;

	gHttpDeamon.clear();
	InitializeCriticalSection(&stcsHttp);

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)clearHttp,this, 0, 0));

	gSSLDeamon.clear();
	InitializeCriticalSection(&stcsSSL);

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)clearSSL, this, 0, 0));
}

Deamon::~Deamon() {

}




int Deamon::closeHTTP(LPHTTPPROXYPARAM lphttp) {
	int ret = 0;

	if (lphttp->sockToClient > 0)
	{
		ret = closesocket(lphttp->sockToClient);
		lphttp->sockToClient = 0;
	}

	if (lphttp->sockToServer > 0)
	{
		ret = closesocket(lphttp->sockToServer);
		lphttp->sockToServer = 0;
	}

	gHttpDeamon.erase(lphttp);

	delete lphttp;

	return ret;
}

int __stdcall Deamon::clearHttp(Deamon * instance) {

	int cnt = 0;
	while (true)
	{
		Sleep(instance->LOOP_TIME);

		EnterCriticalSection(&instance->stcsHttp);

		__try
		{
			unordered_map <LPHTTPPROXYPARAM, LPHTTPPROXYPARAM>::iterator it;
			time_t now = time(0);
			for (it = instance->gHttpDeamon.begin(); it != instance->gHttpDeamon.end(); it++) {
				LPHTTPPROXYPARAM lphttp = it->second;
				if ((now - lphttp->timeclient > instance->gOverTime) || (now - lphttp->timeserver > instance->gOverTime)) {
					instance->closeHTTP(lphttp);
				}
			}
		}
		__except(1) 
		{
			log("%s %d exception\r\n", __FUNCTION__, __LINE__);
		}

		LeaveCriticalSection(&instance->stcsHttp);

		if (cnt++ % OUTPUT_TIMES == 0)
		{
			log( "[%s %d] alive http proxy thread count:%u\r\n", __FUNCTION__, __LINE__, instance->gHttpDeamon.size());
		}
	}
	return 0;
}



int Deamon::addHttp(LPHTTPPROXYPARAM lphttp) {
	if (lphttp <= 0)
	{
		return -1;
	}

	EnterCriticalSection(&gDeamon->stcsHttp);

	__try
	{
		unordered_map <LPHTTPPROXYPARAM, LPHTTPPROXYPARAM>::iterator it;
		it = gDeamon->gHttpDeamon.find(lphttp);
		if (it == gDeamon->gHttpDeamon.end())
		{
			pair< std::unordered_map< LPHTTPPROXYPARAM, LPHTTPPROXYPARAM >::iterator, bool > ret;
			ret = gDeamon->gHttpDeamon.insert(pair<LPHTTPPROXYPARAM, LPHTTPPROXYPARAM>(lphttp, lphttp));
			if (ret.second == false)
			{
				log("%s %d error\r\n", __FUNCTION__, __LINE__);
			}
			else {

			}
		}
		else {
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
		}
	}
	__except (1)
	{
		log("%s %d exception\r\n", __FUNCTION__, __LINE__);
	}

	LeaveCriticalSection(&gDeamon->stcsHttp);

	return 0;
}

int Deamon::removeHttp(LPHTTPPROXYPARAM lphttp) {
	if (lphttp <= 0)
	{
		return -1;
	}
	int ret = 0;

	EnterCriticalSection(&gDeamon->stcsHttp);
	__try
	{
		unordered_map <LPHTTPPROXYPARAM, LPHTTPPROXYPARAM>::iterator it = gDeamon->gHttpDeamon.find(lphttp);
		if (it != gDeamon->gHttpDeamon.end())
		{
			gDeamon->closeHTTP(lphttp);
		}
	}
	__except (1)
	{
		log("%s %d exception\r\n", __FUNCTION__, __LINE__);
	}

	LeaveCriticalSection(&gDeamon->stcsHttp);
	return 0;
}










int Deamon::addSSL(LPSSLPROXYPARAM lpssl) {
	if (lpssl <= 0)
	{
		return -1;
	}

	EnterCriticalSection(&gDeamon->stcsSSL);

	__try
	{
		unordered_map <LPSSLPROXYPARAM, LPSSLPROXYPARAM>::iterator it = gDeamon->gSSLDeamon.find(lpssl);
		if (it == gDeamon->gSSLDeamon.end())
		{
			pair< std::unordered_map< LPSSLPROXYPARAM, LPSSLPROXYPARAM >::iterator, bool > ret;
			ret = gDeamon->gSSLDeamon.insert(pair<LPSSLPROXYPARAM, LPSSLPROXYPARAM>(lpssl, lpssl));
			if (ret.second == false)
			{
				log("%s %d error\r\n", __FUNCTION__, __LINE__);
			}
			else {

			}
		}
		else {
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
		}
	}
	__except (1)
	{
		log("%s %d exception\r\n", __FUNCTION__, __LINE__);
	}

	LeaveCriticalSection(&gDeamon->stcsSSL);
	return 0;
}


int Deamon::closeSSL(LPSSLPROXYPARAM lpssl) {
	int ret = 0;

	if (lpssl->SSLToServer > 0)
	{
		SSL_shutdown(lpssl->SSLToServer);
		SSL_free(lpssl->SSLToServer);
		lpssl->SSLToServer = 0;
	}

	if (lpssl->ctxToServer > 0)
	{
		SSL_CTX_free(lpssl->ctxToServer);
		lpssl->ctxToServer = 0;
	}

	if (lpssl->sockToServer > 0)
	{
		ret = closesocket(lpssl->sockToServer);
		lpssl->sockToServer = 0;
	}

	if (lpssl->SSLToClient > 0)
	{
		SSL_shutdown(lpssl->SSLToClient);
		SSL_free(lpssl->SSLToClient);
		lpssl->SSLToClient = 0;
	}

	if (lpssl->ctxToClient > 0)
	{
		SSL_CTX_free(lpssl->ctxToClient);
		lpssl->ctxToClient = 0;
	}

	if (lpssl->sockToClient > 0)
	{
		ret = closesocket(lpssl->sockToClient);
		lpssl->sockToClient = 0;
	}

	gDeamon->gSSLDeamon.erase(lpssl);
	delete lpssl;

	ERR_remove_state(0);

	ENGINE_cleanup();
	CONF_modules_unload(1);

	CONF_modules_free();
	//ERR_remove_thread_state(NULL);

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	return ret;

	//sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
// 	STACK_OF(SSL_COMP) * ssl_comp_methods = SSL_COMP_get_compression_methods();
// 	int n = sk_SSL_COMP_num(ssl_comp_methods);
// 	for ( int i = 0; i < n; i ++)
// 	{
// 		SSL_COMP *sslcomp = sk_SSL_COMP_delete(ssl_comp_methods,i);
// 	}
// 	sk_SSL_COMP_free(ssl_comp_methods);
}

int Deamon::removeSSL(LPSSLPROXYPARAM lpssl) {
	int ret = 0;
	if (lpssl <= 0)
	{
		return -1;
	}

	EnterCriticalSection(&gDeamon->stcsSSL);
	__try
	{
		unordered_map <LPSSLPROXYPARAM, LPSSLPROXYPARAM>::iterator it = gDeamon->gSSLDeamon.find(lpssl);
		if (it != gDeamon->gSSLDeamon.end())
		{
			gDeamon->closeSSL(lpssl);
		}
	}
	__except (1)
	{
		log("%s %d exception\r\n", __FUNCTION__, __LINE__);
	}

	LeaveCriticalSection(&gDeamon->stcsSSL);
	return 0;
}

int __stdcall Deamon::clearSSL(Deamon *instance) {

	int cnt = 0;

	while (true)
	{
		Sleep(instance->LOOP_TIME);

		EnterCriticalSection(&instance->stcsSSL);

		__try {
			time_t now = time(0);
			unordered_map <LPSSLPROXYPARAM, LPSSLPROXYPARAM>::iterator it;
			for (it = instance->gSSLDeamon.begin(); it != instance->gSSLDeamon.end(); it++) {
				LPSSLPROXYPARAM lpssl = it->second;
				
				if ((now - lpssl->timeclient > instance->gOverTime) || (now - lpssl->timeserver > instance->gOverTime)) {
					instance->closeSSL(lpssl);
					continue;
				}
			}
		}
		__except (1) {
			log("%s %d exception\r\n", __FUNCTION__, __LINE__);
		}

		LeaveCriticalSection(&instance->stcsSSL);

		if (cnt++ % OUTPUT_TIMES == 0)
		{
			log("[%s %d] alive ssl proxy thread count:%u\r\n", __FUNCTION__, __LINE__, instance->gSSLDeamon.size());
		}

	}
	return 0;
}

