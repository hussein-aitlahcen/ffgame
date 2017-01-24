#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN PVOID FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessThreadByCid(
	IN PCLIENT_ID ClientId,
	OUT PEPROCESS * Process,
	OUT PETHREAD * Thread
);

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(IN PEPROCESS Process);

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#define FFGAME_DEVICE_NAME L"ffgame"
#define FFGAME_DEVICE_FILE L"\\\\.\\" FFGAME_DEVICE_NAME

#define DEVICE_NAME     L"\\Device\\"     ## FFGAME_DEVICE_NAME
#define DOS_DEVICE_NAME L"\\DosDevices\\" ## FFGAME_DEVICE_NAME

#define FILE_DEVICE_FFGAME 0x8888

#define IOCTL_FFGAME_COPY_MEMORY  (ULONG)CTL_CODE(FILE_DEVICE_FFGAME, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_FFGAME_INJECT_DLL (ULONG)CTL_CODE(FILE_DEVICE_FFGAME, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#pragma pack(push, 1)
typedef struct _copy_memory_t
{
	ULONGLONG LocalPtr;
	ULONGLONG TargetPtr;
	ULONGLONG PtrSize;
	ULONG     TargetProcessId;
	BOOLEAN   Write;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _inject_dll_t
{
	PWCHAR ProcessName;
	PWCHAR FullDllPath;
} INJECT_DLL, *PINJECT_DLL;
#pragma pack(pop)
