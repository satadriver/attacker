
#include <windows.h>
#include <stdio.h>

#include "windivert.h"
#include "windivert_device.h"
#include <winsock.h>

#pragma comment(lib,"lib/windivert.lib")

#ifdef WINDIVERT_KERNEL
#undef WINDIVERT_KERNEL
#endif

#define MAX_DIVERT_PACKET 0x10000


 int __stdcall winDivert(DWORD dwip) {

	int result = 0;
	char* packet = new char[MAX_DIVERT_PACKET];
	int packetLen = MAX_DIVERT_PACKET;
	WINDIVERT_ADDRESS addr;
	UINT32 recvSize = 0;

	PWINDIVERT_IPHDR iphdr;
	PWINDIVERT_TCPHDR tcphdr;
	PWINDIVERT_UDPHDR udphdr;

	// 打开过滤对象
	
	HANDLE mHandle = WinDivertOpen("outbound  and (tcp.DstPort == 443 or tcp.SrcPort == 443)", //过滤规则
		WINDIVERT_LAYER_NETWORK, //过滤的层
		0, 0);
	if (mHandle == INVALID_HANDLE_VALUE) //开启过滤对象，可以通过错误码识别错误
	{
		result = GetLastError();
		return 0;  //error
	}

	while (1)
	{
		result = WinDivertRecv(mHandle,  // windivert对象
			packet, packetLen,  //char* packet和buff长度
			&recvSize,   // int 实际读取的数据长度
			&addr);
		// 接收过滤到的网络包内容
		if (result == 0) //WINDIVERT_ADDRESS
		{
			result = GetLastError();
			break;
			// error
		}
		//  网络包头部解析
		result = WinDivertHelperParsePacket(packet, recvSize,
			&iphdr, NULL, NULL, NULL, NULL,
			&tcphdr, &udphdr, NULL, NULL, NULL, NULL);
		if (result == 0)
		{
			result = GetLastError();
			break;
			// error
		}

		static DWORD dstip = 0;

		//*(DWORD*)(packet + 16) = dwip;
		//*(DWORD*)(packet + 16) = 0x0100007f;
		//*(DWORD*)(packet + 16) = 0x08080808;
		if (tcphdr->DstPort == 443) {
			dstip = *(DWORD*)(packet + 16);
			*(DWORD*)(packet + 16) = 0x8c6ea8c0;
		}
		else {
			*(DWORD*)(packet + 20) = dstip;
		}
		// 计算校验和
		result = WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
		// 把修改后的包发送出去
		result = WinDivertSend(mHandle, packet, packetLen, &recvSize, &addr);
		if (result == 0)
		{
			result = GetLastError();
			break;
			// send error
		}
	}
	return 0;
}

