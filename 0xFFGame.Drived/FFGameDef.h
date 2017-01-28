#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <wdm.h>
#include <windef.h>

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	IN PEPROCESS pFromProcess,
	IN PVOID pFromAddress,
	IN PEPROCESS pToProcess,
	OUT PVOID pToAddress,
	IN SIZE_T Length,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessThreadByCid(
	IN PCLIENT_ID pClientId,
	OUT PEPROCESS * pProcess,
	OUT PETHREAD * pThread
);

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(IN PEPROCESS pProcess);


NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(IN PEPROCESS pProcess);

NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb(IN PETHREAD pThread);

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(IN PEPROCESS pProcess);

NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	IN ULONG ProcessInformationLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	__out_bcount(ThreadInformationLength) PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength
);

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	//PVOID Reserved1[2]; // LIST_ENTRY
	LIST_ENTRY InLoadOrderLinks;

	LIST_ENTRY InMemoryOrderLinks;

	//PVOID Reserved2[2]; // LIST_ENTRY
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;
	PVOID SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		PVOID SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#define FFGAME_DEVICE_NAME L"ffgame"
#define FFGAME_DEVICE_FILE L"\\\\.\\" FFGAME_DEVICE_NAME

#define DEVICE_NAME     L"\\Device\\"     ## FFGAME_DEVICE_NAME
#define DOS_DEVICE_NAME L"\\DosDevices\\" ## FFGAME_DEVICE_NAME

#define FILE_DEVICE_FFGAME 0x8888

#define IOCTL_FFGAME_COPY_MEMORY  (ULONG)CTL_CODE(FILE_DEVICE_FFGAME, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_FFGAME_INJECT_DLL (ULONG)CTL_CODE(FILE_DEVICE_FFGAME, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
