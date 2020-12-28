#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>
#include <string>
#include <Winternl.h>
#include <iostream>
#pragma comment(lib, "ntdll.lib")
#pragma warning(disable: 4996)

bool isTestMode() 
{
	typedef NTSTATUS(__stdcall* td_NtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	struct SYSTEM_CODEINTEGRITY_INFORMATION 
	{
		ULONG Length;
		ULONG CodeIntegrityOptions;
	};

	static td_NtQuerySystemInformation NtQuerySystemInformation = (td_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	SYSTEM_CODEINTEGRITY_INFORMATION Integrity = {sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0 };

	NTSTATUS status = NtQuerySystemInformation(103, &Integrity, sizeof(Integrity), NULL);
	//printf("Teste : %X\n", Integrity.CodeIntegrityOptions);
	if (Integrity.CodeIntegrityOptions == 0x1)
	{
		printf("Poduto normal: \n");
		printf("CodeIntegrityOptions: %X\n", Integrity.CodeIntegrityOptions);
		return 0;
	}
	else
	{
		printf("Poduto em teste mode: \n");
		printf("CodeIntegrityOptions: %X\n", Integrity.CodeIntegrityOptions);
		return 1;
	}
}

int main()
{
	while (1)
	{
		if (GetAsyncKeyState(VK_F9) & 1)
		{
			isTestMode();
		}
	}
	getchar();
	system("pause");
}