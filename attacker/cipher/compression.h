
#ifndef COMP_UNCOMP_H_H_H
#define COMP_UNCOMP_H_H_H

#include "../include\\zlib.h"
#include "../include\\zconf.h"
#include <string>

using namespace std;


class Compress {
public:

	static int gzfiledata(Byte *data, uLong ndata, Byte *zdata, uLong *zndata);
	static int Compress::gzfile(string srcfn, string dstfn,int withname,string ingzfn);

	static int zcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);
	static int Compress::zdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);

	static int Compress::gzcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);
	static int Compress::gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
	static int Compress::httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);


};


#endif