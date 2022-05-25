#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "PAKCrypt.h"

static const unsigned char *p_tab1;
static const unsigned char *p_tab2;

static unsigned char init_parm[4] = { 0x36, 0x05, 0xbf, 0xce };

static unsigned char tab1[] =
{
	0xf8, 0x96, 0x54, 0x41,
	0xc7, 0x04, 0xb8, 0x41,
	0x7c, 0x5d, 0xbe, 0x07,
	0x6b, 0x62, 0x54, 0xc1,
};

static unsigned char tab2[] =
{
	0x15, 0xa0, 0x38, 0x25,
	0x35, 0x1c, 0xad, 0x5b,
	0x6d, 0x52, 0x7a, 0x36,
	0xa8, 0x17, 0x1d, 0x20,
};

#define SZ_KEYS (sizeof(tab1)/sizeof(unsigned int))

void SetKey(unsigned int key, CryptographyContext* crypt_param){
	crypt_param->Key=key;
	crypt_param->IV=1;
}

static unsigned int GenerateKey(unsigned int key, unsigned int IV)
{
	unsigned char i;
	unsigned int lo, hi, temp, TempIV;

	for(i=0; i<SZ_KEYS; i++)
	{
		TempIV=IV;
		temp = TempIV ^ get_u32(p_tab1+(i*4));

		hi = ((temp >> 16) & 0xffff);
		lo = ((temp) & 0xffff);
		temp = (lo * lo) + ~(hi * hi);
		temp = (temp << 16) | (temp >> 16);

		IV = temp ^ get_u32(p_tab2+(i*4));
		IV += lo * hi;
		IV ^= key;
		key = TempIV;
	}

	return IV;
}

void cipher(void *buffer, unsigned int size, CryptographyContext* crypt_param)
{
	unsigned char *p_buff = buffer;
	unsigned int res, offset = 0;
	unsigned char key[4];
	CryptographyContext temp;

	temp.Key = ~(crypt_param->Key - 1);
	temp.IV = crypt_param->IV;

	while(size > offset)
	{
		if(!(offset & 3))
		{
			res = GenerateKey(temp.Key, temp.IV);
			key[3] = res;
			key[2] = res >>= 1;
			key[1] = res >>= 1;
			key[0] = res >>= 1;
			temp.IV++;
		}

		*p_buff++ ^= key[offset++ & 3];
	}

	crypt_param->IV = temp.IV;
}

static unsigned int crc32_table[256];

static unsigned int crc_reflect(unsigned int ref, unsigned int ch)
{
	unsigned int value = 0, i;

	for(i = 1; i < (ch + 1); i++)
	{
		if(ref & 1) value |= 1 << (ch - i);
		ref >>= 1;
	}

	return value;
}

void crc_init(void)
{
	#define POLY 0x04c11db7

	unsigned int i, j;

	for(i = 0; i <= 256 - 1; i++)
	{
		crc32_table[i] = crc_reflect(i, 8) << 24;
		for (j = 0; j < 8; j++) crc32_table[i] = (crc32_table[i] << 1) ^ (crc32_table[i] & (1 << 31) ? POLY : 0);
		crc32_table[i] = crc_reflect(crc32_table[i], 32);
	}
}

unsigned int get_crc(unsigned char *p, unsigned int len, unsigned int crc)
{
	while(len--) crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ *p++];
	return ~crc;
}

int InitCryptographyContext(unsigned int IV, CryptographyContext* crypt_param)
{
	unsigned int Table1_CRC32, Table2_CRC32;

	/* These tables are not going to be written to. They seem to be used for initializing the key. */
	static const unsigned char t_tab1[] = {
		0xbc, 0x1f, 0x46, 0x64,
		0x09, 0x99, 0x82, 0x34,
		0xc0, 0x25, 0x4f, 0xe5,
		0xb7, 0xdb, 0x26, 0x25,
	};
	static const unsigned char t_tab2[] = {
		0x35, 0xe0, 0xb8, 0x25,
		0x9d, 0x4d, 0x0e, 0x1d,
		0xdc, 0x31, 0xbc, 0xbb,
		0x78, 0xb6, 0x5e, 0xa7,
	};

	printf("IV=0x%08x\n", IV);

	p_tab1 = t_tab1;
	p_tab2 = t_tab2;

	crypt_param->Key = 0x6C69746E;
	crypt_param->IV = IV;
	cipher(init_parm, sizeof(init_parm), crypt_param);

	cipher(tab1, sizeof(tab1), crypt_param);
	cipher(tab2, sizeof(tab2), crypt_param);

	p_tab1 = tab1;
	p_tab2 = tab2;

	SetKey(get_u32(init_parm), crypt_param);

	printf(	"CRC checksums:\n"	\
		"\tCipher key table 1:\t0x%08x\n"	\
		"\tCipher key table 2:\t0x%08x\n", (Table1_CRC32=get_crc(tab1, sizeof(tab1), -1)), (Table2_CRC32=get_crc(tab2, sizeof(tab2), -1)));

	return((Table1_CRC32 != 0x5CBE2D0F || Table2_CRC32 != 0x7BA1A34F)?0:1);
}

