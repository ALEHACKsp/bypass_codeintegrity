#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>

#include "detours.h"

#pragma comment(lib, "detours.lib")

using namespace std;

typedef NTSTATUS(__stdcall* td_NtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
td_NtQuerySystemInformation pfn_NtQuerySystemInformation;

NTSTATUS hk_NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS status;
	printf("_____________________________\n");
	printf("[hook] iniciando: \n");
	printf("[hook] SystemInformationClass: %X \n", SystemInformationClass);

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
	{
		ULONG Length;
		ULONG CodeIntegrityOptions;
	}SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

	_SYSTEM_CODEINTEGRITY_INFORMATION Integrity;
	Integrity.CodeIntegrityOptions = 1;
	Integrity.Length = 0x8;

	//PVOID espaco = VirtualAlloc(NULL,0xC,)

	//PSYSTEM_CODEINTEGRITY_INFORMATION FalseInt = (PSYSTEM_CODEINTEGRITY_INFORMATION)0x70000;
	//FalseInt->CodeIntegrityOptions = 1;
	//FalseInt->Length = 0x8;

	status = pfn_NtQuerySystemInformation(SystemInformationClass, &Integrity, SystemInformationLength, ReturnLength);

	if (SystemInformationClass == 0x67)
	{	

		if (Integrity.CodeIntegrityOptions != 1)
		{
			printf("[hook] Original CodeIntegrityOptions: %X\n", Integrity.CodeIntegrityOptions);
			printf("[hook] Mudando protecao: \n");	

			PSYSTEM_CODEINTEGRITY_INFORMATION false_code_integrity = (PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation;
			false_code_integrity->CodeIntegrityOptions = 0x1;
			false_code_integrity->Length = Integrity.Length;

			return pfn_NtQuerySystemInformation(SystemInformationClass, &false_code_integrity, SystemInformationLength, ReturnLength);

		}
	}

	printf("_____________________________\n\n");
	return status;
}

DWORD WINAPI Thread_inicial(VOID)
{
	DWORD_PTR NtQuerySystemInformation_Addr = (DWORD_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	pfn_NtQuerySystemInformation = (td_NtQuerySystemInformation)NtQuerySystemInformation_Addr;

#ifdef _WIN64
	//
	(VOID)DetourTransactionBegin();
	(VOID)DetourUpdateThread(GetCurrentThread());
	(VOID)DetourAttach(&(PVOID&)pfn_NtQuerySystemInformation, hk_NtQuerySystemInformation);
	(VOID)DetourTransactionCommit();

#else
	//Do you detour for x32
	//Its very easy
	//

#endif




	return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		AllocConsole();
		freopen("CONOUT$", "w", stdout); //console para teste
		DisableThreadLibraryCalls(hModule);
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Thread_inicial, 0, 0, 0);

	}
	return TRUE;
}