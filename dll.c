#include <stdio.h>
#include <Windows.h>

int WINAPI 
DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved){
	switch(fdwReason){
		case DLL_PROCESS_ATTACH:{
			MessageBox(NULL, TEXT("DLL�ѽ���Ŀ�����"), TEXT("��Ϣ"), MB_ICONINFORMATION);
		}
		break;
		case DLL_PROCESS_DETACH:{
			MessageBox(NULL, TEXT("DLL�Ѵ�Ŀ�����ж��"), TEXT("��Ϣ"), MB_ICONINFORMATION);
		}
		break;
	}
	
	return 1;
}
