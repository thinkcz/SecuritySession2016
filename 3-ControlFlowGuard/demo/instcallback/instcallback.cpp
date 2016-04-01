// cfghookdll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "instcallback.h"
#include "imagehlp.h"
#include "windows.h"
#include <stdio.h>
#include <tchar.h>
#include <winternl.h>
#include <thread>
#include <mutex>


#pragma comment (lib, "imagehlp.lib")


extern "C" void InstHookProc();

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;


typedef NTSTATUS(NTAPI  PNtSetInformationProcess)(HANDLE  ProcessHandle,PROCESS_INFORMATION_CLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength);





HANDLE ghMutex = 0;
BOOL bHookDLL = false;


extern "C" ULONG  __fastcall InstrumentationHook(PVOID address, DWORD ReturnCode)
{
	
	TEB* teb = (TEB*)__readgsqword(0x30);

	UCHAR* instr = ((UCHAR*)(teb))+0x2ec;
	*instr = 1;

		//char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
	//	PIMAGEHLP_SYMBOL pimgsym = (PIMAGEHLP_SYMBOL)buffer;
		//ULONG_PTR disp = 0;

	//	pimgsym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
	//	pimgsym->MaxNameLength = MAX_SYM_NAME;

	//	BOOL bret = SymGetSymFromAddr(GetCurrentProcess(), (ULONG_PTR)address, &disp, pimgsym);

	//	if (bret) {

		//	printf("call to %p (%s+%lx)\n", address, pimgsym->Name, disp);
	//	}
	//	else {
			printf("call to %p \n", address);
	//	}
	
		
		*instr = 0;


		return ReturnCode;

}



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
	
	// tell others we are in
	printf("* Injected into victim !");

	// get ntdll module
	HMODULE hModule = GetModuleHandleW(L"NTDLL.DLL");


	// get NtSetInformationProcess
	PNtSetInformationProcess* pNtSetInformationProcess;
	pNtSetInformationProcess = (PNtSetInformationProcess*)GetProcAddress(hModule, "NtSetInformationProcess");

	// fill PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, this is different structure in Windows7
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici;
	ZeroMemory(&pici, sizeof(pici));
	// set HookProc
	pici.Callback = InstHookProc;
	// set
	pNtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS) 0x28, &pici, sizeof(pici));
	





	


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

