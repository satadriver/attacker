
#include <windows.h>



int __stdcall WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {

	MessageBoxA(0, "you are under attack", "you are under attack", MB_OK);

	return 0;
}