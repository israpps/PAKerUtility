#pragma push
#pragma pack(1)

#define PAK_HEADER_FLAG_ENCRYPTED		0x200
struct pak_header_data {
	char magic[4];
	unsigned short int flags;	/* Bit #9 = Fields below encrypted or not (Set = encrypted, cleared = unencrypted). */
	unsigned short int unknown1;
	unsigned int block_sz;
	unsigned int num_entries;
};

#define PAK_ENTRY_FLAG_ENCRYPTED	0x80000000
struct pak_entry_data {
	unsigned int flags;		/* Bit #31 = Fields below and payload encrypted or not (Set = encrypted, cleared = unencrypted). */
	unsigned int startsector; // byte offset = startsector * 2048
	unsigned int filesize;
	char ident[4];
	unsigned int unknown2;
	unsigned int checksum;	/* CRC32 checksum. */
	int unknown4;
	int unknown5;
	unsigned char namelen;
	char filepath[255];
};

struct FileGenListEnt{
	char filename[256];
	char ident[5];
};

#pragma pop

/* Function prototypes. */
int LoadPAKFile(FILE *file, struct PAKFileData *PAKFileData);
int ExtractFilePAKFile(FILE *infp, unsigned int index, struct PAKFileData* PAKFileData, unsigned int *checksum_out);
void UnloadPAKFile(struct PAKFileData *PAKFileData);
int ListPAKFile(const char *filename);
int GeneratePAKFileManifest(const char *filename, const char *ManifestFilename);
int DumpPAKFile(const char *filename);
int CreatePAKFile(const char *filename, unsigned int NumFiles, struct FileGenListEnt *FileList);
int LoadFileList(const char *filename, struct FileGenListEnt **FileList);
