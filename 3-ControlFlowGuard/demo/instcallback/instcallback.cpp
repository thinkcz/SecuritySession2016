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


typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;


typedef NTSTATUS(NTAPI * PNtSetInformationProcess)(HANDLE  ProcessHandle,PROCESS_INFORMATION_CLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength);


extern "C"  void InstHookProc();


HANDLE ghMutex = 0;
BOOL bHookDLL = false;


extern "C" void  InstrumentationHook(void* addr, void* d)
{
	static bool breentrant = false;



	if (!breentrant) {
		breentrant = true;

//		DWORD dwWaitResult = WaitForSingleObject(
			//ghMutex,    // handle to mutex
			//INFINITE);  // no time-out interval
			
		

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


//		ReleaseMutex(ghMutex);


		breentrant = false;
	}
	




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
	
	printf("* Injected into victim !");

	
	HMODULE hModule = GetModuleHandleW(L"NTDLL.DLL");


	PNtSetInformationProcess* pNtSetInformationProcess;

	

	pNtSetInformationProcess = (PNtSetInformationProcess*)GetProcAddress(hModule, "NtSetProcessInformation");

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici;
	ZeroMemory(&pici, sizeof(pici));
	
	pici.Callback = InstHookProc;


	//pNtSetInformationProcess()
	





	


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

