#include <stdio.h> 
#include <winsock2.h> 
#include <iphlpapi.h> 

#pragma comment(lib,"ws2_32") 
#pragma comment(lib,"Iphlpapi") 


int main(int argc, char* argv[]) {
	
	int ret = 0;
	WSAData wsa = { 0 };
	ret = WSAStartup(0x0202, &wsa);
	if (ret )
	{
		printf("init error\r\n");
		getchar();
		return -1;
	}

	if (argc != 3) {
		fprintf(stderr, "Usage: %s inet_addr\n", argv[0]);
		getchar();
		return -1;
	}
	ULONG targetIP = inet_addr(argv[1]);
	if (targetIP == INADDR_NONE) {
		fprintf(stderr, "Invalid IP: %s\n", argv[1]);
		getchar();
		return -1;
	}
	ULONG macBuf[16] = { 0 };
	ULONG macLen = 16;

	//填什么IP都可以，Windows不处理这个参数 
	ULONG localIP = inet_addr(argv[2]);

	DWORD retValue = SendARP(targetIP, localIP, macBuf, &macLen);
	if (retValue != NO_ERROR) {
		ret = GetLastError();
		fprintf(stderr, "SendARP error\n");
		getchar();
		return -1;
	}
	unsigned char *mac = (unsigned char*)macBuf;
	printf("%s --> ", argv[1]);
	for (int i = 0; i < macLen; i++) {
		printf("%.2X", mac[i]);
		if (i != macLen - 1) {
			printf("-");
		}
	}
	printf("\n");

	getchar();
	return 0;
}