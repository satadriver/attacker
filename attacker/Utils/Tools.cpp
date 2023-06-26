#include "Tools.h"
#include <windows.h>
#include <TlHelp32.h>
#include "../SSL/sslPublic.h"
#include "../HttpUtils.h"

#pragma comment(lib,"Netapi32.lib")

#include <mstcpip.h>

#define SOCKET_ALIVE_SECOND 30

//���ִ���TIME_WAIT wait_close
//netstat -an | find "TIME_WAIT" /C
int Tools::setNetworkParams() {
	int ret = 0;

	closeException();

	int maxuserport = 65535;
	//��ֵ�ķ�Χ�Ǵ�5000��65534��ȱʡֵΪ5000�����齫��ֵ����Ϊ65534
	//�����ȱʡֵ��ʮ���Ƶ�5000����Ҳ��ϵͳ�������Сֵ��WindowsĬ��Ϊ��������ʱ���˿ڱ����Ķ˿ںŷ�Χ�Ǵ�1024��5000��
	//Ϊ�˻�ø��ߵĲ����������齫��ֵ������Ϊ32768���ϣ�������Ϊ�������ֵ65534
	char maxportcmd[1024];
	wsprintfA(maxportcmd,
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxUserPort\" /t REG_DWORD /d %u /f",
		maxuserport);
	ret = system(maxportcmd);
	printf("set MaxUserPort:%u retcode:%u\r\n", maxuserport, ret);

	//�����ȱʡֵ��240�����ȴ�4���Ӻ��ͷ���Դ��ϵͳ֧�ֵ���СֵΪ30�����ȴ�ʱ��Ϊ30��
	string timewaitcmdformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpTimedWaitDelay\" /t REG_DWORD /d %u /f";
	char timewaitcmd[1024];
	wsprintfA(timewaitcmd, timewaitcmdformat.c_str(), SOCKET_ALIVE_SECOND);
	ret = system(timewaitcmd);
	printf("set time_wait retcode:%u\r\n", ret);

	//ȱʡ����£��������������7200000���루2Сʱ����û�л��ϵͳ�ͻᷢ�ͱ������ӵ���Ϣ
	// ͨ������Ѹ�ֵ��Ϊ1800000���룬�Ӷ���ʧ�����ӻ���30�����ڱ���⵽
	string kpaliveformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"KeepAliveTime\" /t REG_DWORD /d %u /f";
	char kpalive[1024];
	wsprintfA(kpalive, kpaliveformat.c_str(), SOCKET_ALIVE_SECOND *1000);
	ret = system(kpalive);
	printf("set keep alive retcode:%u\r\n", ret);

	
	//KeepAliveInterval��ֵ��ʾδ�յ���һ���ԡ��������ӡ��źŵ���Ӧʱ��ϵͳ�ظ����͡��������ӡ��źŵ�Ƶ�ʡ�
	//�����κ���Ӧ������£��������͡��������ӡ��źŵĴ�������TcpMaxDataRetransmissions�����Ľ����ܣ���ֵʱ��������������
	string kpaliveintervalformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"KeepAliveInterval\" /t REG_DWORD /d %u /f";
	char kpaliveinternalcmd[1024];
	wsprintfA(kpaliveinternalcmd, kpaliveintervalformat.c_str(), SOCKET_ALIVE_SECOND * 1000);
	ret = system(kpaliveinternalcmd);
	printf("setalive internal retcode:%u\r\n", ret);

	//TcpMaxDataRetransmissions��ֵ��ʾTCP�����ط���ϵͳ�����������϶���Ӧ������ݶν����ط��Ĵ���
	string tcpretransformat =
		"reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpMaxDataRetransmissions\" /t REG_DWORD /d %u /f";
	char tcpretrans[1024];
	wsprintfA(tcpretrans, tcpretransformat.c_str(), 3);
	ret = system(tcpretrans);
	printf("set tcp retrransfer times retcode:%u\r\n", ret);

	
	//Default = RAM dependent, but usual Pro = 1000, Srv=2000
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxFreeTcbs\" /t REG_DWORD /d 65536 /f");
	//MaxHashTableSize ������Ϊ��MaxFreeTcbs ��4�����������Դ������TCP�������ٶȡ�
	//Default = 512, Range = 64-65536 ���ֵ������2���ݣ������Ϊ65536
	//��ֵ�ķ�Χ�Ǵ�1��65536�����ұ���Ϊ2��N�η���ȱʡֵΪ������������ƽ����������Ϊ��������������4��
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxHashTableSize\" /t REG_DWORD /d 65536 /f");


	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpNumConnections\" /t REG_DWORD /d 16777214 /f");


	//TCPWindowSize��ֵ��ʾTCP�Ĵ��ڴ�С��
	//TCP Receive Window��TCP���ݽ��ջ��壩�����˷��Ͷ���û�л�ý��ն˵�ȷ����Ϣ��״̬�¿��Է��͵�����ֽ�����
	//����ֵԽ�󣬷��ص�ȷ����Ϣ��Խ�٣���Ӧ���ڷ��Ͷ˺ͽ��ն�֮���ͨ�ž�Խ�á�
	//����ֵ��Сʱ���Խ��ͷ��Ͷ��ڵȴ����ն˷���ȷ����Ϣʱ������ʱ�Ŀ����ԣ����⽫��������������������Ч�����ʡ�
	//TCP�ڷ��Ͷ˺ͽ��ն�֮�䶯̬����һ�����γ���MSS��Maximum Segment Size������������
	//MSS�����ӿ�ʼ����ʱȷ��������TCP Receive Window������ΪMSS���������������ݴ�������ȫ���ȵ�TCP���ݶεı������ӣ��ʶ���������������ʡ�
	//ȱʡ����£�TCP����ͼ����MSS���Ż����ڴ�С����ʼֵΪ16KB�����ֵΪ64KB��
	//TCPWindowSize�����ֵͨ��Ϊ65535�ֽڣ�64KB������̫�����γ���Ϊ1460�ֽڣ�����64KB��1460�����������Ϊ62420�ֽڣ�
	//���������ע����н�TCPWindowSize����Ϊ62420����Ϊ�ߴ������������õ������Ż�ֵ
	//44��1460
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TCPWindowSize\" /t REG_DWORD /d 62420 /f");

	//���Ͷ˺ͽ��ն�����ͨ�������ʱ�䱻��Ϊ�ػ�ʱ�䣨RTT����
	//TCP Window Scaling����TCP���ӵ�˫��������ʱ��������Ч��TCP��һ��ʱ���ѡ�
	//ͨ������Ƶ���ؼ��������RTTֵ�Ĺ���ֵ����ѡ���ر������ڹ����������Ĺ����������ӵ�RTTֵ�������Ӿ�ȷ�ص���TCP�ط���ʱʱ��
	//system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TCP1323Opts\" /t REG_DWORD /d 65536 /f");


	//TcpMaxConnectRetransmisstions��ֵ��ʾTCP�����ط���TCP�˳�ǰ�ط���ȷ����������SYN���Ĵ���������ÿ�γ��ԣ��ط���ʱ�ǳɹ��ط���������
	//��Windows Server 2003��Ĭ�ϳ�ʱ������2��Ĭ�ϳ�ʱʱ��Ϊ3�루��ע�����TCPInitialRTT�У�
	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"TcpMaxConnectRetransmisstions\" /t REG_DWORD /d 2 /f");

	ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /v \"MaxDataRetries\" /t REG_DWORD /d 2 /f");

	
	//TcpAckFrequency��ֵ��ʾϵͳ����Ӧ����Ϣ��Ƶ�ʡ�
	//���ֵΪ2����ôϵͳ���ڽ��յ�2���ֶ�֮����Ӧ�𣬻����ڽ��յ�1���ֶε���200������û�н��յ��κ������ֶε�����·���Ӧ��
	//���ֵΪ3����ôϵͳ���ڽ��յ�3���ֶ�֮����Ӧ�𣬻����ڽ��յ�1����2���ֶε���200������û�н��յ��κ������ֶε�����·���Ӧ��
	//�Դ����ơ����Ҫͨ������Ӧ���ӳ���������Ӧʱ�䣬��ô���齫��ֵ��Ϊ1
	//ret = system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\����GUID" /v \"TcpAckFrequency\" /t REG_DWORD /d 65536 /f");

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