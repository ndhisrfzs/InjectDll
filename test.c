#include <stdio.h>
#include "Inject.h"

int 
main(int argc, char *argv[]){

	if(!LoadRemoteDll(TEXT("explorer.exe"), TEXT("F:\\C-Project\\AdjustProcess\\x64\\Debug\\dll.dll"))){
		printf("LoadRemoteDll failed");
		return 0;
	}
	if (!UnLoadRemoteDll(TEXT("explorer.exe"), TEXT("F:\\C-Project\\AdjustProcess\\x64\\Debug\\dll.dll")))
	{
		printf("UnLoadRemoteDll failed");
		return 0;
	}
	printf("Inject over\n");

	return 0;
}