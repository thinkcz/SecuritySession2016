// cfghookdll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "cfghookdll.h"
#include "imagehlp.h"
#include "windows.h"
#include <stdio.h>
#include <tchar.h>
#include <winternl.h>
#include <thread>
#include <mutex>


#pragma comment (lib, "imagehlp.lib")


typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.  
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.  
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.  
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.  
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.  
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.  
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.  
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.  
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.  
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.  
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef const PLDR_DLL_NOTIFICATION_DATA PCLDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);
typedef NTSTATUS(NTAPI *pfnLdrRegisterDllNotification)(ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction, void* Context, void **Cookie);
typedef NTSTATUS(NTAPI *pfnLdrUnregisterDllNotification)(void *Cookie);

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1   
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2  


extern "C" void  CfgHook(void* addr)
{
	static bool breentrant = false;

	if (!breentrant) {
		breentrant = true;

		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PIMAGEHLP_SYMBOL pimgsym = (PIMAGEHLP_SYMBOL)buffer;
		ULONG_PTR disp = 0;

		pimgsym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
		pimgsym->MaxNameLength = MAX_SYM_NAME;

		BOOL bret = SymGetSymFromAddr(GetCurrentProcess(), (ULONG_PTR)addr, &disp, pimgsym);

		if (bret) {

			printf("call to %p (%s+%lx)\n", addr, pimgsym->Name, disp);
		}
		else {
			printf("call to %p \n", addr);
		}

		breentrant = false;
	}
	
}


void LoadedDLL(PVOID DllBase, WCHAR* DllName)
{
	
	PIMAGE_NT_HEADERS pnth = ImageNtHeader(DllBase);

	if (pnth->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
	{
		ULONG size;
		
		PIMAGE_LOAD_CONFIG_DIRECTORY loadconfig;
		
		DWORD old = 0;

		printf("Dll Loaded with CFG: %p at %S \n", DllBase, DllName);

		loadconfig = (PIMAGE_LOAD_CONFIG_DIRECTORY)ImageDirectoryEntryToData(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);

		VirtualProtect((PVOID)loadconfig->GuardCFCheckFunctionPointer, sizeof(PVOID), PAGE_READWRITE, &old);
		
		*(PVOID*)loadconfig->GuardCFCheckFunctionPointer = (PVOID)(ULONG_PTR)CfgHook;
		
		VirtualProtect((PVOID)loadconfig->GuardCFCheckFunctionPointer, sizeof(PVOID), old, NULL);

	}
	else {
		printf("Dll Loaded with:     %p at %S \n", DllBase, DllName);
	}

	
}

VOID NTAPI MyLdrDllNotification(
	ULONG NotificationReason,
	PCLDR_DLL_NOTIFICATION_DATA NotificationData,
	PVOID Context
	)
{
	switch (NotificationReason)
	{
	case LDR_DLL_NOTIFICATION_REASON_LOADED:

		LoadedDLL(NotificationData->Loaded.DllBase, NotificationData->Loaded.FullDllName->Buffer);

		
		break;
	case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
		printf("Dll Unloaded: %S \n", NotificationData->Unloaded.FullDllName->Buffer);
		break;
	}
}
// This is an example of an exported function.
void EntryPoint(void* ctx)
{
	
    // open debug console for victim	
	if (AllocConsole()) {
		freopen("CONOUT$", "w", stdout);
		SetConsoleTitle(_T("Debug Console"));
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
	}
	


	// symbols resolving
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(GetCurrentProcess(), NULL, TRUE);
	
	printf("* Injected into victim !");

	
	HMODULE hModule = GetModuleHandleW(L"NTDLL.DLL");

	//   
	pfnLdrRegisterDllNotification pLdrRegisterDllNotification = (pfnLdrRegisterDllNotification)GetProcAddress(hModule, "LdrRegisterDllNotification");
	pfnLdrUnregisterDllNotification pLdrUnregisterDllNotification = (pfnLdrUnregisterDllNotification)GetProcAddress(hModule, "LdrUnregisterDllNotification");
	void *pvCookie = NULL;

	//   
	pLdrRegisterDllNotification(0, MyLdrDllNotification, NULL, &pvCookie);




	


}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		EntryPoint(NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}