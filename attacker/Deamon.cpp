
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

Deamon *gDeamon = 0;


Deamon::Deamon() {
	if (gDeamon || mInstance)
	{
		return;
	}

	mInstance = this;
	gDeamon = this;

		LOOP_TIME = CONNECTION_TIME_OUT + 60000;
	gOverTime = LOOP_TIME /1000;

	gHttpDeamon.clear();
	InitializeCriticalSection(&stcsHttp);

	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)clearHttp,this, STACK_SIZE_PARAM_IS_A_RESERVATION, 0));


	gSSLDeamon.clear();
	InitializeCriticalSection(&stcsSSL);

	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)clearSSL, this, STACK_SIZE_PARAM_IS_A_RESERVATION, 0));
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
	int ret = 0;
	char szout[1024];
	int cnt = 0;

	char buf[NETWORK_BUFFER_SIZE];
	while (true)
	{
		Sleep(instance->LOOP_TIME);

		EnterCriticalSection(&instance->stcsHttp);

		__try
		{
			unordered_map <LPHTTPPROXYPARAM, LPHTTPPROXYPARAM>::iterator it;
			for (it = instance->gHttpDeamon.begin(); it != instance->gHttpDeamon.end(); ) {
				LPHTTPPROXYPARAM lphttp = it->second;
				it++;

				time_t now = time(0);

				if ((now - lphttp->timeclient > instance->gOverTime) || (now - lphttp->timeserver > instance->gOverTime)) {
					instance->closeHTTP(lphttp);
					continue;
				}
			}
		}
		__except(1) 
		{
			printf("clearHttp exceiption\r\n");
		}

		LeaveCriticalSection(&instance->stcsHttp);

		cnt++;
		if (cnt >= OUTPUT_TIMES)
		{
			cnt = 0;
			string datetime = Public::getDateTime();
			int outlen = wsprintfA(szout, "%s clearHttp() alive http proxy thread count:%u\r\n", datetime.c_str(), instance->gHttpDeamon.size());
			Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);
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
				printf("Deamon insert http error\r\n");
			}
			else {

			}
		}
		else {
			printf("Deamon lphttp alread exist\r\n");
		}
	}
	__except (1)
	{
		printf("addHttp exception\r\n");
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
		printf("removeHttp exception\r\n");
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
				printf("Deamon insert ssl error\r\n");
			}
			else {

			}
		}
		else {
			printf("Deamon ssl alread exist\r\n");
		}
	}
	__except (1)
	{
		printf("addSSL exception\r\n");
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
		printf("removeSSL exception\r\n");
	}

	LeaveCriticalSection(&gDeamon->stcsSSL);
	return 0;
}

int __stdcall Deamon::clearSSL(Deamon *instance) {
	int ret = 0;
	char szout[1024];
	int cnt = 0;

	char buf[NETWORK_BUFFER_SIZE];
	while (true)
	{
		Sleep(instance->LOOP_TIME);

		EnterCriticalSection(&instance->stcsSSL);

		__try {
			unordered_map <LPSSLPROXYPARAM, LPSSLPROXYPARAM>::iterator it;
			for (it = instance->gSSLDeamon.begin(); it != instance->gSSLDeamon.end(); ) {
				LPSSLPROXYPARAM lpssl = it->second;
				it++;

				time_t now = time(0);
				if ((now - lpssl->timeclient > instance->gOverTime) || (now - lpssl->timeserver > instance->gOverTime)) {
					instance->closeSSL(lpssl);
					continue;
				}
			}
		}
		__except (1) {
			printf("clearSSL exception\r\n");
		}

		LeaveCriticalSection(&instance->stcsSSL);

		cnt++;

		if (cnt >= OUTPUT_TIMES)
		{
			cnt = 0;
			string datetime = Public::getDateTime();
			int outlen = wsprintfA(szout, "%s clearSSL() alive ssl proxy thread count:%u\r\n", datetime.c_str(), instance->gSSLDeamon.size());
			Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);
		}

	}
	return 0;
}