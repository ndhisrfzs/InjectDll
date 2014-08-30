#include <stdio.h>
#include <Windows.h>

int WINAPI 
DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved){
	switch(fdwReason){
		case DLL_PROCESS_ATTACH:{
			MessageBox(NULL, TEXT("DLL已进入目标进程"), TEXT("信息"), MB_ICONINFORMATION);
		}
		break;
		case DLL_PROCESS_DETACH:{
			MessageBox(NULL, TEXT("DLL已从目标进程卸载"), TEXT("信息"), MB_ICONINFORMATION);
		}
		break;
	}
	
	return 1;
}
