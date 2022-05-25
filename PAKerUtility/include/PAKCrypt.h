/* WARNING! Do not remove the brackets around "x" as they are required to prevent unintended errors caused by the change in the order of operation. */

#ifdef BIG_ENDIAN
	#define BSWAP32(x) (((x)<<24)|((x&0xff00)<<8)|(((x)&0xff0000)>>8)|((x)>>24))
	#define get_u32(x) (BSWAP32(*(unsigned int *)(x)))
#else
	#define get_u32(x) (*(unsigned int *)(x))
#endif

typedef struct CryptographyContext
{
	unsigned int Key;
	unsigned int IV;
} CryptographyContext;

/* Function prototypes */
void crc_init(void);
unsigned int get_crc(unsigned char *p, unsigned int len, unsigned int crc);
int InitCryptographyContext(unsigned int IV, CryptographyContext* crypt_param);
void SetKey(unsigned int key, CryptographyContext* crypt_param);
void cipher(void *buffer, unsigned int size, CryptographyContext* crypt_param);

