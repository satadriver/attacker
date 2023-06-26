#include "Tools.h"
#include <windows.h>
#include <TlHelp32.h>
#include "../SSL/sslPublic.h"
#include "../HttpUtils.h"

#pragma comment(lib,"Netapi32.lib")

#include <mstcpip.h>

#define SOCKET_ALIVE_SECOND 30

//发现大量TIME_WAIT wait_close
//netstat -an | find "TIME_WAIT" /C
int Tools::setNetworkParams() {
	int ret = 0;

	closeException();

	int maxuserport = 65535;
	//该值的范围是从5000到65534，缺省值为5000，建议将该值设置为65534
	//该项的缺省值是十进制的5000，这也是系统允许的最小值。Windows默认为匿名（临时）端口保留的端口号范围是从1024到5000。
	//为了获得更高的并发量，建议将该值至少设为32768以上，甚至设为理论最大值65534
	char maxportcmd[1024];
	wsprintfA(maxportcmd,
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxUserPort\" /t REG_DWORD /d %u /f",
		maxuserport);
	ret = system(maxportcmd);
	printf("set MaxUserPort:%u retcode:%u\r\n", maxuserport, ret);

	//该项的缺省值是240，即等待4分钟后释放资源；系统支持的最小值为30，即等待时间为30秒
	string timewaitcmdformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpTimedWaitDelay\" /t REG_DWORD /d %u /f";
	char timewaitcmd[1024];
	wsprintfA(timewaitcmd, timewaitcmdformat.c_str(), SOCKET_ALIVE_SECOND);
	ret = system(timewaitcmd);
	printf("set time_wait retcode:%u\r\n", ret);

	//缺省情况下，如果空闲连接在7200000毫秒（2小时）内没有活动，系统就会发送保持连接的消息
	// 通常建议把该值设为1800000毫秒，从而丢失的连接会在30分钟内被检测到
	string kpaliveformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"KeepAliveTime\" /t REG_DWORD /d %u /f";
	char kpalive[1024];
	wsprintfA(kpalive, kpaliveformat.c_str(), SOCKET_ALIVE_SECOND *1000);
	ret = system(kpalive);
	printf("set keep alive retcode:%u\r\n", ret);

	
	//KeepAliveInterval的值表示未收到另一方对“保持连接”信号的响应时，系统重复发送“保持连接”信号的频率。
	//在无任何响应的情况下，连续发送“保持连接”信号的次数超过TcpMaxDataRetransmissions（下文将介绍）的值时，将放弃该连接
	string kpaliveintervalformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"KeepAliveInterval\" /t REG_DWORD /d %u /f";
	char kpaliveinternalcmd[1024];
	wsprintfA(kpaliveinternalcmd, kpaliveintervalformat.c_str(), SOCKET_ALIVE_SECOND * 1000);
	ret = system(kpaliveinternalcmd);
	printf("setalive internal retcode:%u\r\n", ret);

	//TcpMaxDataRetransmissions的值表示TCP数据重发，系统在现有连接上对无应答的数据段进行重发的次数
	string tcpretransformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpMaxDataRetransmissions\" /t REG_DWORD /d %u /f";
	char tcpretrans[1024];
	wsprintfA(tcpretrans, tcpretransformat.c_str(), 3);
	ret = system(tcpretrans);
	printf("set tcp retrransfer times retcode:%u\r\n", ret);

	
	//Default = RAM dependent, but usual Pro = 1000, Srv=2000
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxFreeTcbs\" /t REG_DWORD /d 65536 /f");
	//MaxHashTableSize 被配置为比MaxFreeTcbs 大4倍，这样可以大大增加TCP建立的速度。
	//Default = 512, Range = 64-65536 这个值必须是2的幂，且最大为65536
	//该值的范围是从1到65536，并且必须为2的N次方，缺省值为处理器个数的平方，建议设为处理器核心数的4倍
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxHashTableSize\" /t REG_DWORD /d 65536 /f");


	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpNumConnections\" /t REG_DWORD /d 16777214 /f");


	//TCPWindowSize的值表示TCP的窗口大小。
	//TCP Receive Window（TCP数据接收缓冲）定义了发送端在没有获得接收端的确认信息的状态下可以发送的最大字节数。
	//此数值越大，返回的确认信息就越少，相应的在发送端和接收端之间的通信就越好。
	//此数值较小时可以降低发送端在等待接收端返回确认信息时发生超时的可能性，但这将增加网络流量，降低有效吞吐率。
	//TCP在发送端和接收端之间动态调整一个最大段长度MSS（Maximum Segment Size）的整数倍。
	//MSS在连接开始建立时确定，由于TCP Receive Window被调整为MSS的整数倍，在数据传输中完全长度的TCP数据段的比例增加，故而提高了网络吞吐率。
	//缺省情况下，TCP将试图根据MSS来优化窗口大小，起始值为16KB，最大值为64KB。
	//TCPWindowSize的最大值通常为65535字节（64KB），以太网最大段长度为1460字节，低于64KB的1460的最大整数倍为62420字节，
	//因而可以在注册表中将TCPWindowSize设置为62420，作为高带宽网络中适用的性能优化值
	//44个1460
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TCPWindowSize\" /t REG_DWORD /d 62420 /f");

	//发送端和接收端往返通信所需的时间被称为回环时间（RTT）。
	//TCP Window Scaling仅在TCP连接的双方都开启时才真正有效。TCP有一个时间戳选项，
	//通过更加频繁地计算来提高RTT值的估测值，此选项特别有助于估测更长距离的广域网上连接的RTT值，并更加精确地调整TCP重发超时时间
	//system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TCP1323Opts\" /t REG_DWORD /d 65536 /f");


	//TcpMaxConnectRetransmisstions的值表示TCP连接重发，TCP退出前重发非确认连接请求（SYN）的次数。对于每次尝试，重发超时是成功重发的两倍。
	//在Windows Server 2003中默认超时次数是2，默认超时时间为3秒（在注册表项TCPInitialRTT中）
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpMaxConnectRetransmisstions\" /t REG_DWORD /d 2 /f");

	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxDataRetries\" /t REG_DWORD /d 2 /f");

	
	//TcpAckFrequency的值表示系统发送应答消息的频率。
	//如果值为2，那么系统将在接收到2个分段之后发送应答，或是在接收到1个分段但在200毫秒内没有接收到任何其他分段的情况下发送应答；
	//如果值为3，那么系统将在接收到3个分段之后发送应答，或是在接收到1个或2个分段但在200毫秒内没有接收到任何其他分段的情况下发送应答，
	//以此类推。如果要通过消除应答延迟来缩短响应时间，那么建议将该值设为1
	//ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\网卡GUID" /v \"TcpAckFrequency\" /t REG_DWORD /d 65536 /f");

	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"EnableDynamicBacklog\" /t REG_DWORD /d 1 /f");
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MinimumDynamicBacklog\" /t REG_DWORD /d 128 /f");
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaximumDynamicBacklog\" /t REG_DWORD /d 2048 /f");
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"DynamicBacklogGrowthDelta\" /t REG_DWORD /d 128 /f");

	return 0;
}




int Tools::getNumberOfCPU() {

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwNumberOfProcessors;
}



int Tools::autorun(string username, string password, int cardno) {
	char szcurpath[MAX_PATH];
	int ret = GetModuleFileNameA(0, szcurpath, MAX_PATH);
	char szRuCmd[1024];
	wsprintfA(szRuCmd, "\"%s\" %s %s %u", szcurpath, username.c_str(), password.c_str(), cardno);
	string szkeyformat1 = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v AUTORUN /t REG_SZ /d \"%s\" /f";
	char szcmd[1024];
	string szkeyformat2 = "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v AUTORUN /t REG_SZ /d \"%s\" /f";

	string szkeyformat3 = "reg add HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run /v AUTORUN /t REG_SZ /d \"%s\" /f";

	int cmdlen = wsprintfA(szcmd, szkeyformat1.c_str(), szRuCmd);
	ret = WinExec(szcmd, SW_SHOW);

	cmdlen = wsprintfA(szcmd, szkeyformat2.c_str(), szRuCmd);
	ret = WinExec(szcmd, SW_SHOW);

	cmdlen = wsprintfA(szcmd, szkeyformat3.c_str(), szRuCmd);
	ret = WinExec(szcmd, SW_SHOW);
	return ret;
}



int Tools::GetWindowsVersion()
{
	WKSTA_INFO_100 *wkstaInfo = NULL;
	NET_API_STATUS netStatus = NetWkstaGetInfo(NULL, 100, (LPBYTE *)&wkstaInfo);
	if (netStatus == NERR_Success)
	{
		DWORD dwMajVer = wkstaInfo->wki100_ver_major;
		DWORD dwMinVer = wkstaInfo->wki100_ver_minor;
		DWORD dwVersion = (DWORD)MAKELONG(dwMinVer, dwMajVer);
		netStatus = NetApiBufferFree(wkstaInfo);

		int iSystemVersion = 0;
		if (dwVersion < 0x50000)
		{
			iSystemVersion = SYSTEM_VERSION_WIN9X;
		}
		else if (dwVersion == 0x50000)
		{

			iSystemVersion = SYSTEM_VERSION_WIN2000;
		}
		else if (dwVersion > 0x50000 && dwVersion < 0x60000)
		{

			iSystemVersion = SYSTEM_VERSION_XP;
		}
		else if (dwVersion == 0x60000)
		{

			iSystemVersion = SYSTEM_VERSION_VISTA;
		}
		else if (dwVersion == 0x60001)
		{

			iSystemVersion = SYSTEM_VERSION_WIN7;
		}
		else if (dwVersion >= 0x60002 && dwVersion <= 0x60003)
		{

			iSystemVersion = SYSTEM_VERSION_WIN8;
		}
		else if (dwVersion >= 0x60003 || dwVersion == 0x100000)
		{

			iSystemVersion = SYSTEM_VERSION_WIN10;
		}
		else
		{
			iSystemVersion = SYSTEM_VERSION_UNKNOW;
		}
		return iSystemVersion;
	}

	return FALSE;
}


BOOL Tools::Is64bitSystem()
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		return TRUE;
	else
		return FALSE;
}


int Tools::GetCpuBits()
{
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	BOOL bIsWow64 = FALSE;
	//IsWow64Process is not available on all supported versions of Windows
	char szIsWow64Process[] = { 'I','s','W','o','w','6','4','P','r','o','c','e','s','s',0 };
	HMODULE lpDllKernel32 = LoadLibraryA("kernel32.dll");
	LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(lpDllKernel32, szIsWow64Process);
	if (NULL != fnIsWow64Process)
	{
		int iRet = fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
		if (iRet && bIsWow64)
		{
			return 64;
		}
	}
	return 32;
}


DWORD Tools::QueryRegistryValue(HKEY hMainKey, char * szSubKey, char * szKeyName, unsigned char * szKeyValue, int iCpuBits)
{
	unsigned long iType = KEY_READ;
	DWORD dwDisPos = REG_SZ;
	HKEY hKey = 0;
	int iRes = 0;

	int ver = Tools::GetWindowsVersion();
	PVOID dwWow64Value;
	if (ver >= 4)
	{
		if (iCpuBits == 64 && hMainKey == HKEY_LOCAL_MACHINE)
		{
			HMODULE lpDllKernel32 = LoadLibraryA("kernel32.dll");
			typedef void(__stdcall* ptrWow64DisableWow64FsRedirection)(PVOID);
			ptrWow64DisableWow64FsRedirection lpWow64DisableWow64FsRedirection =
				(ptrWow64DisableWow64FsRedirection)GetProcAddress(lpDllKernel32, "Wow64DisableWow64FsRedirection");
			if (lpWow64DisableWow64FsRedirection > 0)
			{
				lpWow64DisableWow64FsRedirection(&dwWow64Value);
				iType |= KEY_WOW64_64KEY;
			}
		}
	}

	//KEY_WEITE will cause error like winlogon
	//winlogon :Registry symbolic links should only be used for for application compatibility when absolutely necessary.
	iRes = RegCreateKeyExA(hMainKey, szSubKey, 0, REG_NONE, REG_OPTION_NON_VOLATILE, iType, 0, &hKey, &dwDisPos);

	if (ver >= 4)
	{
		if (iCpuBits == 64 && hMainKey == HKEY_LOCAL_MACHINE)
		{
			HMODULE lpDllKernel32 = LoadLibraryA("kernel32.dll");
			typedef void(__stdcall* ptrWow64RevertWow64FsRedirection)(PVOID);
			ptrWow64RevertWow64FsRedirection lpWow64RevertWow64FsRedirection =
				(ptrWow64RevertWow64FsRedirection)GetProcAddress(lpDllKernel32, "Wow64RevertWow64FsRedirection");
			if (lpWow64RevertWow64FsRedirection > 0)
			{
				lpWow64RevertWow64FsRedirection(&dwWow64Value);
			}
		}
	}

	if (iRes != ERROR_SUCCESS)
	{
		return FALSE;
	}

	//if value is 234 ,it means out buffer is limit
	//2 is not value
	unsigned long iQueryLen = MAX_PATH;
	iRes = RegQueryValueExA(hKey, szKeyName, 0, &iType, szKeyValue, &iQueryLen);
	if (iRes == ERROR_SUCCESS)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

int Tools::addFirewallPort(unsigned int port, string name, string protocol) {

	//int iRet = WinExec("cmd /c net stop mpssvc",SW_HIDE);
	//int iRet = WinExec("cmd /c netsh advfirewall set privateprofile state off",SW_HIDE);
	//iRet = WinExec("cmd /c netsh advfirewall set publicprofile state off",SW_HIDE);

	char szCmd[1024];

	wsprintfA(szCmd, "netsh advfirewall firewall add rule name=\"%s\" protocol=%s dir=in localport=%u action=allow", name.c_str(), protocol.c_str(), port);
	//wsprintfA(szCmd, "netsh firewall set portopening TCP %u ENABLE", port);
	int iRet = system(szCmd);
	if (iRet)
	{
		printf("firewall open port:%u error\r\n", port);
		return FALSE;
	}

	printf("firewall open port:%u ok\r\n", port);
	return 0;
}






int Tools::getInstallPath(int cpubits,string appname,string & installpath)
{
	char lpSubKey[MAX_PATH] = { 'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\','W','i','n','d','o','w','s','\\',\
		'C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\','U','n','i','n','s','t','a','l','l','\\',0 };

	char strDisplayName[] = { 'D','i','s','p','l','a','y','N','a','m','e',0 };
	char strDisplayVersion[] = { 'D','i','s','p','l','a','y','V','e','r','s','i','o','n',0 };
	char strInstallLoc[] = { 'I','n','s','t','a','l','l','L','o','c','a','t','i','o','n',0 };
	char strPublisher[] = { 'P','u','b','l','i','s','h','e','r',0 };
	char strInstallDate[] = { 'I','n','s','t','a','l','l','D','a','t','e',0 };
	char strUninstall[] = { 'U','n','i','n','s','t','a','l','l','S','t','r','i','n','g',0 };
	
	DWORD dwType = KEY_READ;

	PVOID dwWow64Value = 0;
	//HKEY_LOCAL_MACHINE and 64 bits must use like this
	if (cpubits == 64)
	{
		dwType |= KEY_WOW64_64KEY;
		Wow64DisableWow64FsRedirection(&dwWow64Value);
	}

	HKEY hkResult = 0;
	//DWORD dwDisPos = 0;
	//LONG lReturn = lpRegCreateKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, REG_NONE, REG_OPTION_NON_VOLATILE, dwType, 0, &hkResult, &dwDisPos);
	LONG lReturn = RegOpenKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, dwType, &hkResult);

	if (cpubits == 64)
	{
		Wow64RevertWow64FsRedirection(&dwWow64Value);
	}

	if (lReturn == ERROR_SUCCESS)
	{
		DWORD index = 0;

		SoftInfo softinfo = { 0 };

		char szKeyName[MAX_PATH] = { 0 };
		DWORD dwKeyLen = MAX_PATH;
		int iRet = RegEnumKeyExA(hkResult, index, szKeyName, &dwKeyLen, 0, NULL, NULL, NULL);
		while (ERROR_NO_MORE_ITEMS != iRet && ERROR_SUCCESS == iRet)
		{
			index++;
			if (*szKeyName)
			{
				char strMidReg[MAX_PATH];
				lstrcpyA(strMidReg, lpSubKey);
				lstrcatA(strMidReg, szKeyName);
				HKEY hkRKey = 0;
				if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, strMidReg, 0, dwType, &hkRKey) == ERROR_SUCCESS)
				{
					DWORD subtype = 0;
					*softinfo.m_strSoftName = 0;

					DWORD dwNameLen = MAX_PATH;
					lReturn = RegQueryValueExA(hkRKey, strDisplayName, 0, &subtype, (LPBYTE)softinfo.m_strSoftName, &dwNameLen);

					dwNameLen = MAX_PATH;
					lReturn = RegQueryValueExA(hkRKey, strDisplayVersion, 0, &subtype, (LPBYTE)softinfo.m_strSoftVersion, &dwNameLen);

					dwNameLen = MAX_PATH;
					lReturn = RegQueryValueExA(hkRKey, strInstallLoc, 0, &subtype, (LPBYTE)softinfo.m_strInstallLocation, &dwNameLen);

					dwNameLen = MAX_PATH;
					lReturn = RegQueryValueExA(hkRKey, strPublisher, 0, &subtype, (LPBYTE)softinfo.m_strPublisher, &dwNameLen);

					dwNameLen = MAX_PATH;
					lReturn = RegQueryValueExA(hkRKey, strInstallDate, 0, &subtype, (LPBYTE)softinfo.m_strInstallDate, &dwNameLen);

					dwNameLen = MAX_PATH;
					lReturn = RegQueryValueExA(hkRKey, strUninstall, 0, &subtype, (LPBYTE)softinfo.m_strUninstallPth, &dwNameLen);

					RegCloseKey(hkRKey);

					if (strstr(softinfo.m_strSoftName, appname.c_str()))
					{
						installpath = string(softinfo.m_strInstallLocation);
						RegCloseKey(hkResult);
						return TRUE;
					}
				}
				else {
					iRet = GetLastError();
				}
			}

			dwKeyLen = MAX_PATH;
			*szKeyName = 0;
			iRet = RegEnumKeyExA(hkResult, index, szKeyName, &dwKeyLen, 0, NULL, NULL, NULL);
		}
		RegCloseKey(hkResult);
	}

	return 0;
}


void Tools::closeException() {
	system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Windows Error Reporting\" /v \"DontShowUI\" /t REG_DWORD /d 1 /f");
}