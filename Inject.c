#include "Inject.h"

typedef DWORD (WINAPI *PFNTCREATETHREADEX)  
(   
	PHANDLE                 ThreadHandle,     
	ACCESS_MASK             DesiredAccess,    
	LPVOID                  ObjectAttributes,     
	HANDLE                  ProcessHandle,    
	LPTHREAD_START_ROUTINE  lpStartAddress,   
	LPVOID                  lpParameter,      
	BOOL                    CreateSuspended,      
	DWORD64                 dwStackSize,      
	DWORD64                 dw1,
	DWORD64                 dw2,
	LPVOID                  Unknown   
); 

static BOOL 
EnablePrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege){
	BOOL bResult = FALSE;
	HANDLE hToken;
	TOKEN_PRIVILEGES priv = {1, {0, 0, 0}};
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
		goto error;
	}
	if(!LookupPrivilegeValue(NULL, lpszPrivilege, &priv.Privileges[0].Luid)){
		goto error;
	}

	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

	if(!AdjustTokenPrivileges(hToken, FALSE, &priv, sizeof(priv), 0, 0)){
		goto error;
	}
	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED){
		goto error;
	}

	bResult = TRUE;
error:
	if (hToken != NULL){
		CloseHandle(hToken);
	}

	return bResult;
}

static BOOL 
GetProcessIdByName(LPCWSTR szProcessName, LPDWORD lpPID){
	STARTUPINFO st;
	PROCESS_INFORMATION pi;
	PROCESSENTRY32 ps;
	HANDLE hSnapshot = NULL;
	ZeroMemory(&st, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	st.cb = sizeof(STARTUPINFO);
	ZeroMemory(&ps, sizeof(PROCESSENTRY32));
	ps.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot == INVALID_HANDLE_VALUE){
		goto error;
	}

	if (!Process32First(hSnapshot, &ps)){
		goto error;
	}

	do{
		if(lstrcmpiW(ps.szExeFile, szProcessName) == 0){
			*lpPID = ps.th32ProcessID;
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}
	while (Process32Next(hSnapshot, &ps));
	
error:
	if (hSnapshot != NULL){
		CloseHandle(hSnapshot);
	}

	return FALSE;
}

static HMODULE 
GetProcessModuleByName(DWORD dwProcessId, LPCWSTR lpszLibName){
	HANDLE hSnapshot = NULL; 
	MODULEENTRY32 me = {sizeof(MODULEENTRY32)}; 
	BOOL bFound = FALSE; 

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId); 
	if (hSnapshot == NULL) 
		goto error;

	if(!Module32FirstW(hSnapshot, &me)){
		goto error;
	}

	do{
		if((lstrcmpiW(me.szModule, lpszLibName) == 0) || (lstrcmpiW(me.szExePath, lpszLibName) == 0)) {
			CloseHandle(hSnapshot);
			return me.hModule;
		}
	} while (Module32NextW(hSnapshot, &me));

error:
	if (hSnapshot != NULL) 
		CloseHandle(hSnapshot); 

	return NULL;
}

static BOOL 
IsVistaOrLater(){  
	OSVERSIONINFO osvi;  
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));  
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);  
	GetVersionEx(&osvi);  
	if(osvi.dwMajorVersion >= 6)  
		return TRUE;  
	return FALSE;  
}  

static HANDLE 
MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf){  
	HANDLE      hThread = NULL;  
	FARPROC     pFunc = NULL;  
	if(IsVistaOrLater()){  // Vista, 7, Server2008 
		pFunc = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");  
		if( pFunc == NULL ){
			return FALSE;  
		}  
		((PFNTCREATETHREADEX)pFunc)(
			&hThread,  
			0x1FFFFF,  
			NULL,  
			hProcess,  
			pThreadProc,  
			pRemoteBuf,  
			FALSE,  
			(DWORD64)NULL,  
			(DWORD64)NULL,  
			(DWORD64)NULL,  
			(LPVOID)NULL);  
		if( hThread == NULL){  
			return NULL;  
		}  
	}else{                      // 2000, XP, Server2003  
		hThread = CreateRemoteThread(hProcess,   
			NULL,   
			0,   
			pThreadProc,   
			pRemoteBuf,   
			0,   
			NULL);  
		if( hThread == NULL ){  
			return NULL;  
		}  
	}  
	
	return hThread;  
}

BOOL 
LoadRemoteDll(LPCWSTR lpszProcessName, LPCWSTR lpszLibName){
	DWORD dwPID;
	BOOL bResult = FALSE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pszLibFileRemote = NULL;
	DWORD cch;
	DWORD dwBufSize;
	LPTHREAD_START_ROUTINE pfnThreadRtn;

	if(!EnablePrivilege(SE_DEBUG_NAME, TRUE)){
		goto error;
	}
	if(!GetProcessIdByName(lpszProcessName, &dwPID)){
		goto error;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPID);
	if (hProcess == NULL){
		goto error;
	}
	
	cch = 1 + lstrlen(lpszLibName);
	dwBufSize = cch * sizeof(WCHAR);
	pszLibFileRemote = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL){
		goto error;
	}

	if (!WriteProcessMemory(hProcess, pszLibFileRemote, (LPVOID)lpszLibName, dwBufSize, NULL)){
		goto error;
	}

	pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(TEXT("kernel32")), "LoadLibraryW");
	if(pfnThreadRtn == NULL){
		goto error;
	}

	hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pfnThreadRtn, pszLibFileRemote);
	if(hThread == NULL){
		goto error;
	}

	if( WAIT_FAILED == WaitForSingleObject(hThread, INFINITE) ){  
		goto error;  
	}  

	bResult = TRUE;

error:
	if(pszLibFileRemote != NULL){
		VirtualFreeEx(hProcess, (PVOID)pszLibFileRemote, 0, MEM_RELEASE);
	}

	if (hThread != NULL){
		CloseHandle(hThread);
	}

	if (hProcess != NULL){
		CloseHandle(hProcess);
	}

	return bResult;
}

BOOL 
UnLoadRemoteDll(LPCWSTR lpszProcessName, LPCWSTR lpszLibName){ 
	DWORD dwPID;	
	BOOL bResult = FALSE; 
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL; 			
	LPTHREAD_START_ROUTINE pfnThreadRnt = NULL;
	HMODULE hModule = NULL;

	if(!EnablePrivilege(SE_DEBUG_NAME, TRUE)){
		goto error;
	}
	if(!GetProcessIdByName(lpszProcessName, &dwPID)){
		goto error;
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, dwPID); 
	if (hProcess == NULL){
		goto error; 
	}

	pfnThreadRnt = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT( "Kernel32")), "FreeLibrary"); 
	if (pfnThreadRnt == NULL){
		goto error;
	}

	hModule = GetProcessModuleByName(dwPID, lpszLibName);
	if (hModule == NULL){
		goto error;
	}

	hThread = MyCreateRemoteThread(hProcess, pfnThreadRnt, hModule);//me.modBaseAddr);

	if (hThread == NULL){
		goto error; 
	}	

	WaitForSingleObject(hThread, INFINITE); 

	bResult = TRUE; 
error:
	if (hThread != NULL){
		CloseHandle(hThread);
	}

	if (hProcess != NULL){
		CloseHandle(hProcess);
	}

	return bResult; 
} 
