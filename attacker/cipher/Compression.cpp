

#include <windows.h>
#include "../include\\zlib.h"
#include "../include\\zconf.h"
#include "compression.h"
#include "../FileOper.h"
#include "../Public.h"

/* Compress data */
int Compress::zcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;

	if(data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if(deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) 
			return -1;
		c_stream.next_in  = data;
		c_stream.avail_in  = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out  = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) 
		{
			if(deflate(&c_stream, Z_NO_FLUSH) != Z_OK) 
				return -1;
		}
		if(c_stream.avail_in != 0) 
			return c_stream.avail_in;
		for (;;) {
			if((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) 
				break;
			if(err != Z_OK) 
				return -1;
		}
		if(deflateEnd(&c_stream) != Z_OK) 
			return -1;
		*nzdata = c_stream.total_out;
		return 0;
	}
	return -1;
}

/* Uncompress data */
int Compress::zdecompress(Byte *zdata, uLong nzdata,Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream; /* decompression stream */

	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit(&d_stream) != Z_OK) 
		return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if(err != Z_OK) 
			return -1;
	}
	if(inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;
	return 0;
}




//GZIP��ʽ��־ 1f8b

//CM ѹ������(0-7 reserved, 8 = deflate)

//FLG��1 byte������־λ��    
//bit 0 set: FTEXT �ļ�������ASCII�ı��ļ� 
//bit 1 set: FHCRC ���Ӷ��gzip�ļ����� 
//bit 2 set: FEXTRA �����п�ѡ�ĸ��� ���� 
//bit 3 set: FNAME �ṩ��ԭʼ���ļ����� 
//bit 4 set: FCOMMENT ���ṩ��һ��O���ս���ļ����� 
//bit 5 set: �ļ������� 
//bit 6,7:   ���� 

//MTIME��4 byte�����ļ�����ʱ��(Unixʱ��)

//XFL��1 byte�������ӵı�־��������ѹ����������CM = 8ʱ��XFL = 2 �C ���ѹ�����������㷨��XFL = 4 �C ��쵫��Сѹ�����㷨

//OS��1 byte���������־ָ���˽���ѹ��ʱϵͳ�����͡�
//0 �C FAT filesystem (MS-DOS, OS/2, NT/Win32) 
//1 �C Amiga 
//2 �C VMS (or OpenVMS) 
//3 �C Unix 
//4 �C VM/CMS 
//5 �C Atari TOS 
//6 �C HPFS filesystem (OS/2, NT) 
//7 �C Macintosh 
//8 �C Z-System 
//9 �C CP/M 
//10 �C TOPS-20 
//11 �C NTFS filesystem (NT) 
//12 �C QDOS 
//13 �C Acorn RISCOS 
//255 �C unknown 

//ͷ����չ�ֶ�,����˳�������ǣ�FEXTRA+FNAME+FCOMMENT+FHCRC����һ��������ڣ�����ֻҪ���ڣ����۴��ڼ�����һ��Ҫ����˳����

//DATA

//CRC32��4 byte���������δѹ�����ݵ�ѭ������У��ֵ��
//ISIZE��4 byte��������ԭʼ���ݵĳ�����2��32�η�Ϊģ��ֵ��GZIP���ֽ�����˳����LSB��ʽ����Little - Endian����ZLIB�е��෴��

int Compress::gzfiledata(Byte *data, uLong ndata, Byte *gzdata, uLong *ngzdata) {
	DWORD crc = crc32(0, data, ndata);

	int ret = 0;

	memcpy(gzdata, "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03", 10);

	DWORD gzsize = *ngzdata - 18;

	ret = Compress::gzcompress(data, ndata, gzdata + 10, &gzsize);
	memcpy(gzdata + 10 + gzsize, &crc, 4);
	memcpy(gzdata + 10 + gzsize + 4, &ndata, 4);
	
	*ngzdata = gzsize + 18;

	return gzsize + 18;
}


int Compress::gzfile(string srcfn, string dstfn,int withname,string ingzfn) {
	int ret = 0;

	//string filename = Public::getNameFromFullPath(dstfn);
	
	unsigned char * data = 0;
	DWORD ndata = 0;

	ret = FileOper::fileDecryptReader(srcfn,(char**) &data, (int*)&ndata);
	if (ret <= 0)
	{
		return FALSE;
	}

	DWORD crc = crc32(0, data, ndata);

	int ngzdata = ndata + 0x1000;
	unsigned char * gzdata = new unsigned char[ngzdata];

	int gzhdrsize = 10;
	if (withname)
	{
		memcpy(gzdata, "\x1f\x8b\x08\x08\x00\x00\x00\x00\x00\x00", gzhdrsize);

		memcpy(gzdata + gzhdrsize, ingzfn.c_str(), ingzfn.length() + 1);

		gzhdrsize += (ingzfn.length() + 1);
	}
	else {
		memcpy(gzdata, "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00", gzhdrsize);
	}

	DWORD gzsize = ngzdata - gzhdrsize - 8;

	ret = Compress::gzcompress(data, ndata, gzdata + gzhdrsize, &gzsize);
	if (ret < 0)
	{
		delete gzdata;
		return FALSE;
	}

	memcpy(gzdata + gzhdrsize + gzsize, &crc, 4);

	memcpy(gzdata + gzhdrsize + gzsize + 4, &ndata, 4);

	ret = FileOper::fileWriter(dstfn, (char*)gzdata, gzhdrsize + gzsize + 8, 1);

	delete gzdata;

	return gzsize + gzhdrsize + 8;
}


/* Compress gzip data */
int Compress::gzcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;

	if(data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,-MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) 

		//ֻ������ΪMAX_WBITS + 16��������ѹ���ı��д�header��trailer

		//if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		{
			return -1;
		}
			
		c_stream.next_in  = data;
		c_stream.avail_in  = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out  = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) 
		{
			if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK)
			{
				return -1;
			}
		}

		if (c_stream.avail_in != 0)
		{
			return c_stream.avail_in;
		}

		for (;;) {
			if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END)
			{
				break;
			}

			if (err != Z_OK)
			{
				return -1;
			}
		}

		if (deflateEnd(&c_stream) != Z_OK)
		{
			return -1;
		}

		*nzdata = c_stream.total_out;

		return 0;
	}
	return -1;
}



/* HTTP gzip decompress */
int Compress::httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */
	static char dummy_head[2] = 
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit2(&d_stream, 47) != Z_OK) 
		return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if(err != Z_OK )
		{
			if(err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if(inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;
	return 0;
}

/* Uncompress gzip data */
int Compress::gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */
	static char dummy_head[2] = 
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit2(&d_stream, -MAX_WBITS) != Z_OK) 
		return -1;
	//if(inflateInit2(&d_stream, 47) != Z_OK) 
	//return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if(err != Z_OK )
		{
			if(err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if(inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;
	return 0;
}












