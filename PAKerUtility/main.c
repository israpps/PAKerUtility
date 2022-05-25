#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>

#ifdef __unix__
#include <unistd.h>
#elif defined(_WIN32) || defined(WIN32)
#include <direct.h>
#endif

#include "PAK.h"
#include "PAKCrypt.h"
#define SyntaxError "Syntax error.\n"
#define CREATE_PAK_SINTAX  	"Syntax: %s -c <PAK file> <Manifest file>\n"
#define EXTRACT_PAK_SINTAX 	"Syntax: %s -x <PAK file>\n"
#define LIST_PAK_SINTAX		"Syntax: %s -l <PAK file>\n"
#define CREATE_PAK_MANIFEST	"Syntax: %s -m <PAK file> <Manifest file>\n"
static const char* SyntaxErrorMsg= SyntaxError \
					"\tSupported modes of operation:\n"	\
					"\t\t-c\t- Create PAK archive\n"	\
					"\t\t\t" CREATE_PAK_SINTAX \
					"\t\t-x\t- Extract all files from the PAK archive\n"	\
					"\t\t\t" EXTRACT_PAK_SINTAX \
					"\t\t-l\t- List all files present in the PAK archive\n"	\
					"\t\t\t" LIST_PAK_SINTAX \
					"\t\t-m\t- Create a (CSV) manifest file of the PAK archive\n"	\
					"\t\t\t" CREATE_PAK_MANIFEST ;

int main(int argc, char **argv)
{
	int result, NumFiles;
	struct FileGenListEnt *FileList;

	printf(	"PAKer Utility v1.01\n"
			"Recompiled by El_isra\n"
			"Made by SP193\n"
			"---------------------\n\n");

	if(argc<2)
	{
		printf(SyntaxErrorMsg, argv[0], argv[0], argv[0], argv[0]);
		return EINVAL;
	}

	crc_init();

	result=0;
	if(!strcmp(argv[1], "-c")){
		if(argc==4){
			if((NumFiles=LoadFileList(argv[3], &FileList))>0 && FileList!=NULL){
				result=CreatePAKFile(argv[2], NumFiles, FileList);
				free(FileList);
			}
			else{
				result=NumFiles;
				printf("Unable to load file list. Result: %d\n", result);
			}
		}
		else{
			printf(SyntaxError"\t"CREATE_PAK_SINTAX, argv[0]);
			result=EINVAL;
		}

	}
	else if(!strcmp(argv[1], "-x")){
		if(argc==3){
			result=DumpPAKFile(argv[2]);
		}
		else{
			printf(SyntaxError"\t"EXTRACT_PAK_SINTAX, argv[0]);
			result=EINVAL;
		}
	}
	else if(!strcmp(argv[1], "-l")){
		if(argc==3){
			result=ListPAKFile(argv[2]);
		}
		else{
			printf(SyntaxError"\t"LIST_PAK_SINTAX, argv[0]);
			result=EINVAL;
		}
	}
	else if(!strcmp(argv[1], "-m")){
		if(argc==4){
			result=GeneratePAKFileManifest(argv[2], argv[3]);
		}
		else{
			printf(SyntaxError"\t"CREATE_PAK_MANIFEST, argv[0]);
			result=EINVAL;
		}
	}
	else{
		printf("Unrecognized switch: %s\n", argv[1]);
		result=EINVAL;
	}

	return result;
}

