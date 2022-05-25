#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <direct.h>

#include "PAK.h"
#include "PAKCrypt.h"


int LoadPAKFile(FILE *file, struct PAKFileData *PAKFileData){
	CryptographyContext crypt_param;
	unsigned int i;
	int result;

	result=0;
	fread(&PAKFileData->Header, sizeof(PAKFileData->Header), 1, file);

	if(InitCryptographyContext(get_u32(&PAKFileData->Header.magic), &crypt_param)!=0){
		if(PAKFileData->Header.flags&PAK_HEADER_FLAG_ENCRYPTED)	/* Decrypt the header, if it is encrypted. */
		{
			cipher(&PAKFileData->Header.unknown1, sizeof(PAKFileData->Header.unknown1), &crypt_param);
			cipher(&PAKFileData->Header.block_sz, sizeof(PAKFileData->Header.block_sz), &crypt_param);
			cipher(&PAKFileData->Header.num_entries, sizeof(PAKFileData->Header.num_entries), &crypt_param);
		}

		printf("PAK file header - ID: %c%c%c%c, files: %u, Block size: %u, unknown1: 0x%08x\n", PAKFileData->Header.magic[0], PAKFileData->Header.magic[1], PAKFileData->Header.magic[2], PAKFileData->Header.magic[3], get_u32(&PAKFileData->Header.num_entries), PAKFileData->Header.block_sz, PAKFileData->Header.unknown1);

		SetKey(get_u32(&PAKFileData->Header.num_entries)+(1<<31), &crypt_param);
		if((PAKFileData->FileEntries=malloc(sizeof(struct pak_entry_data)*PAKFileData->Header.num_entries))!=NULL){
			fread(PAKFileData->FileEntries, sizeof(struct pak_entry_data), PAKFileData->Header.num_entries, file);

			if(PAKFileData->Header.flags&PAK_HEADER_FLAG_ENCRYPTED){
				for (i = 0; i < get_u32(&PAKFileData->Header.num_entries); i++)
					cipher(&PAKFileData->FileEntries[i], sizeof(struct pak_entry_data), &crypt_param);
			}
		}
		else{
			printf("Error: Unable to allocate memory for the file list.\n");
			result=ENOMEM;
		}
	}
	else{
		printf("Error: Unable to generate key! Possible cause: File format is not supported.\n");
		result=EINVAL;
	}

	return result;
}

int ExtractFilePAKFile(FILE *infp, unsigned int index, struct PAKFileData* PAKFileData, unsigned int *checksum_out){
	FILE* outfp;
	CryptographyContext t_parm;
	unsigned int crc, count, sz;
	unsigned char buffer[4*1024];
	int result;

	result=0;

	{
		char *p_name = PAKFileData->FileEntries[index].filepath;
		int ii = PAKFileData->FileEntries[index].namelen - 1;
		for (; ii > 0; ii --)
		{
			if ((p_name[ii] == '/') || (p_name[ii] == '\\'))
			{
				int iii;
				char slash = p_name[ii];
				p_name[ii] = '\0';
				for (iii = 0; ii > iii;iii ++)
				{
					if ((p_name[iii] == '/') || (p_name[iii] == '\\')) {
						p_name[iii] = '\0';
						mkdir(PAKFileData->FileEntries[index].filepath);
						p_name[iii] = slash;
					}
				}
				mkdir(PAKFileData->FileEntries[index].filepath);
				p_name[ii] = slash;
				break;
			}
		}
	}

	fseek(infp, get_u32(&PAKFileData->FileEntries[index].startsector) * get_u32(&PAKFileData->Header.block_sz), SEEK_SET);

	if(get_u32(&PAKFileData->FileEntries[index].flags)&PAK_ENTRY_FLAG_ENCRYPTED) /* Encrypted file. */
		SetKey(get_u32(&PAKFileData->FileEntries[index].filesize)+get_u32(&PAKFileData->FileEntries[index].flags), &t_parm);

	if((outfp = fopen(PAKFileData->FileEntries[index].filepath, "wb"))!=NULL) {
		for(crc = -1, count = get_u32(&PAKFileData->FileEntries[index].filesize); count > 0 && result==0;)
		{
			sz=count>get_u32(&PAKFileData->Header.block_sz)?get_u32(&PAKFileData->Header.block_sz):count;
			if(fread(buffer, 1, sz, infp)==sz){
				if(get_u32(&PAKFileData->FileEntries[index].flags)&PAK_ENTRY_FLAG_ENCRYPTED) /* Encrypted file. */
					cipher(buffer, sz, &t_parm);

				crc = ~get_crc(buffer, sz, crc);
				fwrite(buffer, sz, 1, outfp);
				count -= sz;
			}
			else{
				result=EIO;
				printf("I/O error occurred while reading file %s.\n", PAKFileData->FileEntries[index].filepath);
			}
		}

		fclose(outfp);
		if(result==0){
			if(checksum_out!=NULL) *checksum_out=~crc;
			result=(get_u32(&PAKFileData->FileEntries[index].checksum) == ~crc)?0:EIO;
		}
	}
	else{
		printf("Error: cannot open %s for writing: %s\n", PAKFileData->FileEntries[index].filepath, strerror(errno));
		result=EIO;
	}

	return result;
}

void UnloadPAKFile(struct PAKFileData *PAKFileData){
	free(PAKFileData->FileEntries);
}

int ListPAKFile(const char *filename){
	unsigned int i;
	struct PAKFileData PAKFileData;
	FILE *infp;
	int result;

	if((infp=fopen(filename, "rb"))!=NULL){
		if((result=LoadPAKFile(infp, &PAKFileData))==0){
			for(i=0; i<PAKFileData.Header.num_entries; i++){
				printf("Index: %u - Ident: %c%c%c%c, filepath: %s, size: %u, checksum: 0x%08x\n", i+1, PAKFileData.FileEntries[i].ident[0], PAKFileData.FileEntries[i].ident[1], PAKFileData.FileEntries[i].ident[2], PAKFileData.FileEntries[i].ident[3], PAKFileData.FileEntries[i].filepath, get_u32(&PAKFileData.FileEntries[i].filesize), PAKFileData.FileEntries[i].checksum);
			}

			UnloadPAKFile(&PAKFileData);
			result=0;
		}

		fclose(infp);
	}
	else{
		printf("Unable to open PAK file: %s\n", filename);
		result=ENOENT;
	}

	return result;
}

int GeneratePAKFileManifest(const char *filename, const char *ManifestFilename){
	unsigned int i;
	struct PAKFileData PAKFileData;
	FILE *infp, *ManfstFile;
	char line[300];
	int result;

	if((infp=fopen(filename, "rb"))!=NULL){
		ManfstFile=fopen(ManifestFilename, "w");
		if((result=LoadPAKFile(infp, &PAKFileData))==0){
			for(i=0; i<PAKFileData.Header.num_entries; i++){
				sprintf(line, "%s;%c%c%c%c\n", PAKFileData.FileEntries[i].filepath, PAKFileData.FileEntries[i].ident[0], PAKFileData.FileEntries[i].ident[1], PAKFileData.FileEntries[i].ident[2], PAKFileData.FileEntries[i].ident[3]);
				fputs(line, ManfstFile);
				printf("Index: %u - Ident: %c%c%c%c, filepath: %s, size: %u, checksum: 0x%08x\n", i+1, PAKFileData.FileEntries[i].ident[0], PAKFileData.FileEntries[i].ident[1], PAKFileData.FileEntries[i].ident[2], PAKFileData.FileEntries[i].ident[3], PAKFileData.FileEntries[i].filepath, get_u32(&PAKFileData.FileEntries[i].filesize), PAKFileData.FileEntries[i].checksum);
			}

			UnloadPAKFile(&PAKFileData);
			result=0;
		}

		fclose(infp);
		fclose(ManfstFile);
	}
	else{
		printf("Unable to open PAK file: %s\n", filename);
		result=ENOENT;
	}

	return result;
}

int DumpPAKFile(const char *filename){
	unsigned int i, crc_f, checksum;
	struct PAKFileData PAKFileData;
	FILE *infp;
	int result;

	if((infp=fopen(filename, "rb"))!=NULL){
		if((result=LoadPAKFile(infp, &PAKFileData))==0){
			mkdir("extracted");
			chdir("extracted");

			for(i=0,crc_f=0; i<PAKFileData.Header.num_entries; i++){
				printf("Index: %u - Ident: %c%c%c%c, filepath: %s, size: %u, ", i+1, PAKFileData.FileEntries[i].ident[0], PAKFileData.FileEntries[i].ident[1], PAKFileData.FileEntries[i].ident[2], PAKFileData.FileEntries[i].ident[3], PAKFileData.FileEntries[i].filepath, get_u32(&PAKFileData.FileEntries[i].filesize));
				result=ExtractFilePAKFile(infp, i, &PAKFileData, &checksum);

				printf("crc32:");
				if(result==0) printf("OK\n");
				else{
					printf("%s %0X != %0X\n", (crc_f++, "FAIL"), get_u32(&PAKFileData.FileEntries[i].checksum), checksum);
				}
			}

			printf("Files decrypted: %u, Errors: %u\n", PAKFileData.Header.num_entries - crc_f, crc_f);

			fclose(infp);
			UnloadPAKFile(&PAKFileData);
			result=0;
		}
	}
	else{
		printf("Unable to open PAK file: %s\n", filename);
		result=ENOENT;
	}

	return result;
}

int CreatePAKFile(const char *filename, unsigned int NumFiles, struct FileGenListEnt *FileList){
	int result;
	FILE *file, *InputFile;
	CryptographyContext crypt_param, t_parm;
	struct pak_header_data Header;
	struct pak_entry_data *FileEntries;
	unsigned int i, SectorOffset, NameLength, sz, count, crc;
	int size;
	unsigned char buffer[4*1024];

	result=0;
	if((file=fopen(filename, "wb"))!=NULL){
		/* Start by writing the header. */
		Header.magic[0]='f';
		Header.magic[1]='p';
		Header.magic[2]='k';
		Header.magic[3]='r';
		Header.flags=PAK_HEADER_FLAG_ENCRYPTED;
		Header.block_sz=2048;
		Header.unknown1=0;
		Header.num_entries=NumFiles;
		if((FileEntries=malloc(sizeof(struct pak_entry_data)*NumFiles))!=NULL){
			if(InitCryptographyContext(get_u32(&Header.magic), &crypt_param)!=0){
				printf("PAK file header - ID: %c%c%c%c, files: %u, Block size: %u\n", Header.magic[0], Header.magic[1], Header.magic[2], Header.magic[3], get_u32(&Header.num_entries), Header.block_sz);

				size=sizeof(struct pak_header_data)+NumFiles*sizeof(struct pak_entry_data);
				SectorOffset=size/Header.block_sz;
				if(size%Header.block_sz!=0) SectorOffset++;

				for(i = 0; i < NumFiles; i++)
				{
					printf("Adding file %s...", FileList[i].filename);
					if((InputFile=fopen(FileList[i].filename, "rb"))!=NULL){
						fseek(InputFile, 0, SEEK_END);
						size=ftell(InputFile);
						fseek(InputFile, 0, SEEK_SET);

						FileEntries[i].flags=PAK_ENTRY_FLAG_ENCRYPTED;
						FileEntries[i].startsector=SectorOffset;
						memcpy(FileEntries[i].ident, FileList[i].ident, sizeof(FileEntries[i].ident));
						FileEntries[i].filesize=size;

						NameLength=strlen(FileList[i].filename);
						if(NameLength>sizeof(FileEntries[i].filepath)) NameLength=sizeof(FileEntries[i].filepath);
							FileEntries[i].namelen=NameLength;
							strncpy(FileEntries[i].filepath, FileList[i].filename, sizeof(FileEntries[i].filepath));

							if(get_u32(&FileEntries[i].flags)&PAK_ENTRY_FLAG_ENCRYPTED) /* Encrypted file. */
							{
								SetKey(get_u32(&FileEntries[i].filesize)+get_u32(&FileEntries[i].flags), &t_parm);
							}

							fseek(file, FileEntries[i].startsector*Header.block_sz, SEEK_SET);
							for(crc = -1, count = get_u32(&FileEntries[i].filesize); count > 0;)
							{
								sz=count>get_u32(&Header.block_sz)?get_u32(&Header.block_sz):count;
								if(fread(buffer, 1, sz, InputFile)==sz){
									crc = ~get_crc(buffer, sz, crc);

									if (get_u32(&FileEntries[i].flags)&PAK_ENTRY_FLAG_ENCRYPTED) /* Encrypted file. */
										cipher(buffer, sz, &t_parm);

									if(fwrite(buffer, 1, sz, file)==sz){
										count -= sz;
									}else{
										result=EIO;
										break;
									}
								}else{
									result=EIO;
									break;
								}
						}

						fclose(InputFile);
						FileEntries[i].checksum=~crc;

						SectorOffset+=(size/Header.block_sz);
						if(size%Header.block_sz!=0) SectorOffset++;

						fclose(InputFile);
					}else{
						result=ENOENT;
					}

					if(result==0){
						printf("done!\n");
					}else{
						printf("failed!\n");
						break;
					}
				}

				if(result==0){
					/* Finally, write the file header. */
					if(Header.flags&PAK_HEADER_FLAG_ENCRYPTED)	/* Encrypt the header, if it is supposed to be encrypted. */
					{
						cipher(&Header.unknown1, sizeof(Header.unknown1), &crypt_param);
						cipher(&Header.block_sz, sizeof(Header.block_sz), &crypt_param);
						cipher(&Header.num_entries, sizeof(Header.num_entries), &crypt_param);
					}
					fseek(file, 0, SEEK_SET);
					fwrite(&Header, sizeof(struct pak_header_data), 1, file);

					SetKey(NumFiles+(1<<31), &crypt_param);
					for(i = 0; i < NumFiles; i++)
					{
						if(Header.flags&PAK_HEADER_FLAG_ENCRYPTED) cipher(&FileEntries[i], sizeof(struct pak_entry_data), &crypt_param);
						fwrite(&FileEntries[i], sizeof(struct pak_entry_data), 1, file);
					}

					printf("Archive created successfully. Files added: %u.\n", NumFiles);
				}else{
					printf("Failed to create archive.\n");
				}
			}
			else{
				printf("Error: Unable to generate key! Possible cause: Bug.\n");
				result=EINVAL;
			}
		}
		else{
			printf("Error: Unable to allocate memory for the file list.\n");
			result=ENOMEM;
		}

		fclose(file);
		free(FileEntries);

		if(result!=0) remove(filename);
	}
	else{
		printf("Unable to create PAK file: %s\n", filename);
		result=EIO;
	}

	return result;
}

/*
	LoadFileList()
		Arguments:
			const char *filename			- The file name of the CSV manifest file.
			struct FileGenListEnt **FileList	- A pointer to the pointer that shall point to the file list.
		Returned values:
			>=0	= Number of files read in.
			<0	= An error occurred. The error code is multiplied by -1.

		If the pointer pointed to by FileList is not NULL and the function returned with no errors, remember to free the allocated buffer!

*/
int LoadFileList(const char *filename, struct FileGenListEnt **FileList){
	int result;
	FILE *file;
	char buffer[300], *str;
	unsigned int NumFiles, i;

	struct FileGenListNode *first, *prev;
	struct FileGenListNode *CurrentNode;

	printf("Loading file list...");

	result=0;
	*FileList=NULL;
	CurrentNode=NULL;
	if((file=fopen(filename, "r"))!=NULL){
		NumFiles=0;
		while(fgets(buffer, sizeof(buffer), file)!=NULL){
			if(NumFiles==0){
				first=malloc(sizeof(struct FileGenListNode));
				CurrentNode=first;
			}
			else{
				CurrentNode->next=malloc(sizeof(struct FileGenListNode));
				CurrentNode=CurrentNode->next;
			}
			CurrentNode->next=NULL;

			if((str=strtok(buffer, ";"))!=NULL){
				strncpy(CurrentNode->FileListGenEnt.filename, str, sizeof(CurrentNode->FileListGenEnt.filename)-1);
				CurrentNode->FileListGenEnt.filename[sizeof(CurrentNode->FileListGenEnt.filename)-1]='\0';
				if((str=strtok(NULL, ";"))!=NULL) strncpy(CurrentNode->FileListGenEnt.ident, str, sizeof(CurrentNode->FileListGenEnt.ident)-1);
				CurrentNode->FileListGenEnt.ident[sizeof(CurrentNode->FileListGenEnt.ident)-1]='\0';

			//	printf("Filename: %s, Ident: %s\n", CurrentNode->FileListGenEnt.filename, CurrentNode->FileListGenEnt.ident);
			}
			else{
				result=EINVAL;
				break;
			}

			NumFiles++;
		}

		if(result==0) *FileList=malloc(sizeof(struct FileGenListEnt)*NumFiles);
		CurrentNode=first;
		i=0;
		while(CurrentNode!=NULL){
			if((*FileList)!=NULL) memcpy(&(*FileList)[i], &CurrentNode->FileListGenEnt, sizeof(struct FileGenListEnt));//sizeof((*FileList)[i]));
			prev=CurrentNode;
			CurrentNode=CurrentNode->next;
			free(prev);
			i++;
		}
	}
	else result=ENOENT;

	if(result==0){
		printf("done!\n");
		result=NumFiles;
	}else{
		printf("Failed. Error code: %d\n", result);
		result=-result;
	}

	return result;
}

