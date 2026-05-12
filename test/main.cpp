
#include <windows.h>



int __stdcall WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {

	WSADATA wsa;
	WSAStartup(0x202, &wsa);

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr("134.122.169.45");
	sa.sin_port == ntohs(8000);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));



	MessageBoxA(0, "you are under attack", "you are under attack", MB_OK);

	return 0;
}