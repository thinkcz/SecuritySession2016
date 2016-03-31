// injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"



void RaiseError(TCHAR* Reason)
{
	DWORD le = GetLastError();
	_tprintf(_T("%s raised error: %d"), Reason, le);
	TerminateProcess(GetCurrentProcess(), le);
}

int main()
{
	char*	pathtotool = "C:\\users\\marti\\Documents\\Visual StudiO 2015\\Projects\\cfghookdll\\x64\\Debug\\cfghookdll.dll";
	TCHAR*  process = _T("C:\\windows\\system32\\notepad.exe");

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	si.cb = sizeof(STARTUPINFO);
	ZeroMemory(&si, si.cb);
	 


	BOOL bRet = CreateProcess(process, NULL, 0, 0, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!bRet) 
		RaiseError(_T("Creating process"));
	
	void* loadlib = GetProcAddress(GetModuleHandle(_T("kernelbase.dll")), "LoadLibraryA");
	if (!loadlib)
		RaiseError(_T("GetProcAddress"));

	void* path =	VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!path)
		RaiseError(_T("VirtualAlloc in remote thread"));

	

	bRet = WriteProcessMemory(pi.hProcess, path, pathtotool, strlen(pathtotool) + 1, NULL);
	if (!bRet)
		RaiseError(_T("Creating process"));

	// inject dll into remote process
	DWORD  thid = 0;
	HANDLE hThread  = CreateRemoteThreadEx(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)loadlib, (void*)path, 0, 0, &thid);
	if (!hThread)
		RaiseError(_T("Creation of remote process"));


	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);



	// run process
	ResumeThread(pi.hThread);


	
	WaitForSingleObject(pi.hProcess, INFINITE);


	

    return 0;
}

