#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <direct.h>

#include "PAK.h"
#include "PAKCrypt.h"

static const char* SyntaxErrorMsg=	"Syntax error.\n"			\
					"\tSupported modes of operation:\n"	\
					"\t\t/c\t- Create PAK archive\n"	\
					"\t\t\tSyntax: PAKerUtility /c <PAK file> <Manifest file>\n"	\
					"\t\t/x\t- Extract all files from the PAK archive\n"	\
					"\t\t\tSyntax: PAKerUtility /x <PAK file>\n"		\
					"\t\t/l\t- List all files present in the PAK archive\n"	\
					"\t\t\tSyntax: PAKerUtility /l <PAK file>\n"		\
					"\t\t/m\t- Create a (CSV) manifest file of the PAK archive\n"	\
					"\t\t\tSyntax: PAKerUtility /m <PAK file> <Manifest file>\n";

int main(int argc, char **argv)
{
	int result, NumFiles;
	struct FileGenListEnt *FileList;

	printf(	"PAKer Utility v1.01\n"
			"===================\n\n");

	if(argc<2)
	{
		printf(SyntaxErrorMsg);
		return EINVAL;
	}

	crc_init();

	result=0;
	if(!strcmp(argv[1], "/c")){
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
			printf(SyntaxErrorMsg);
			result=EINVAL;
		}

	}
	else if(!strcmp(argv[1], "/x")){
		if(argc==3){
			result=DumpPAKFile(argv[2]);
		}
		else{
			printf(SyntaxErrorMsg);
			result=EINVAL;
		}
	}
	else if(!strcmp(argv[1], "/l")){
		if(argc==3){
			result=ListPAKFile(argv[2]);
		}
		else{
			printf(SyntaxErrorMsg);
			result=EINVAL;
		}
	}
	else if(!strcmp(argv[1], "/m")){
		if(argc==4){
			result=GeneratePAKFileManifest(argv[2], argv[3]);
		}
		else{
			printf(SyntaxErrorMsg);
			result=EINVAL;
		}
	}
	else{
		printf("Unrecognized switch: %s\n", argv[1]);
		result=EINVAL;
	}

	return result;
}

