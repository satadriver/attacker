#pragma once
/**
* The QQ2003C protocol plugin
*
* for gaim
*
* Copyright (C) 2004 Puzzlebird
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*****************************************************************************/
#ifndef _QQ_QQ_CRYPT_H_
#define _QQ_QQ_CRYPT_H_

#define DECRYPT 0x00
#define ENCRYPT 0x01

#ifdef __cplusplus
extern "C"
{
#endif 

	int qq_crypt2(
		unsigned char   flag,
		unsigned char*  instr,
		int             instrlen,
		unsigned char*  key,
		unsigned char*  outstr,
		int*            outstrlen_ptr
	);

	int qq_crypt(
		unsigned char   flag,
		unsigned char*  instr,
		int             instrlen,
		unsigned char*  key,
		unsigned char*  outstr,
		int*            outstrlen_ptr);

	void qq_encrypt(
		unsigned char*  instr,
		int             instrlen,
		unsigned char*  key,
		unsigned char*  outstr,
		int*            outstrlen_prt);

	int qq_decrypt(
		unsigned char*  instr,
		int             instrlen,
		unsigned char*  key,
		unsigned char*  outstr,
		int*            outstrlen_ptr);


#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif


   /*****************************************************************************/

