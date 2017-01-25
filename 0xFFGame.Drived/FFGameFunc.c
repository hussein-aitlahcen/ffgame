#include "FFGameFunc.h"

NTSTATUS FFSafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size)
{
	ASSERT(result != NULL);
	if (result == NULL || size == 0)
		return STATUS_INVALID_PARAMETER;

	result->Buffer = ExAllocatePool(PagedPool, size);
	result->Length = 0;
	result->MaximumLength = size;

	if (result->Buffer)
		RtlZeroMemory(result->Buffer, size);
	else
		return STATUS_NO_MEMORY;

	return STATUS_SUCCESS;
}

NTSTATUS FFSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source)
{
	ASSERT(result != NULL && source != NULL);
	if (result == NULL || source == NULL || source->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;

	// No data to copy
	if (source->Length == 0)
	{
		result->Length = result->MaximumLength = 0;
		result->Buffer = NULL;
		return STATUS_SUCCESS;
	}

	result->Buffer = ExAllocatePool(PagedPool, source->MaximumLength);
	result->Length = source->Length;
	result->MaximumLength = source->MaximumLength;

	memcpy(result->Buffer, source->Buffer, source->Length);

	return STATUS_SUCCESS;
}

LONG FFSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive)
{
	ASSERT(source != NULL && target != NULL);
	if (source == NULL || target == NULL || source->Buffer == NULL || target->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;

	// Size mismatch
	if (source->Length < target->Length)
		return -1;

	USHORT diff = source->Length - target->Length;
	for (USHORT i = 0; i < diff; i++)
	{
		if (RtlCompareUnicodeStrings(
			source->Buffer + i / sizeof(WCHAR),
			target->Length / sizeof(WCHAR),
			target->Buffer,
			target->Length / sizeof(WCHAR),
			CaseInSensitive
		) == 0)
		{
			return i;
		}
	}

	return -1;
}

NTSTATUS FFStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name)
{
	ASSERT(path != NULL && name);
	if (path == NULL || name == NULL)
		return STATUS_INVALID_PARAMETER;

	// Empty string
	if (path->Length < 2)
	{
		*name = *path;
		return STATUS_NOT_FOUND;
	}

	for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
	{
		if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
		{
			name->Buffer = &path->Buffer[i + 1];
			name->Length = name->MaximumLength = path->Length - (i + 1) * sizeof(WCHAR);
			return STATUS_SUCCESS;
		}
	}

	*name = *path;
	return STATUS_NOT_FOUND;
}

NTSTATUS FFStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir)
{
	ASSERT(path != NULL && dir);
	if (path == NULL || dir == NULL)
		return STATUS_INVALID_PARAMETER;

	// Empty string
	if (path->Length < 2)
	{
		*dir = *path;
		return STATUS_NOT_FOUND;
	}

	for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
	{
		if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
		{
			dir->Buffer = path->Buffer;
			dir->Length = dir->MaximumLength = i * sizeof(WCHAR);
			return STATUS_SUCCESS;
		}
	}

	*dir = *path;
	return STATUS_NOT_FOUND;
}

NTSTATUS FFFileExists(IN PUNICODE_STRING path)
{
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK statusBlock = { 0 };
	OBJECT_ATTRIBUTES obAttr = { 0 };
	InitializeObjectAttributes(&obAttr, path, OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwCreateFile(
		&hFile, FILE_READ_DATA | SYNCHRONIZE, &obAttr,
		&statusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
	);

	if (NT_SUCCESS(status))
		ZwClose(hFile);

	return status;
}

NTSTATUS FFSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

PVOID FFGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	__try
	{
		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

												// Wow64 process
		if (isWow64)
		{
			PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
			if (pPeb32 == NULL)
			{
				DPRINT("ffgame: %s: No PEB present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
			{
				DPRINT("ffgame: %s: Loader not intialized, waiting\n", __FUNCTION__);
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			if (!pPeb32->Ldr)
			{
				DPRINT("ffgame: %s: Loader was not intialized in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
				pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
				pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
			{
				UNICODE_STRING ustr;
				PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

				if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
					return (PVOID)pEntry->DllBase;
			}
		}
		else
		{
			PPEB pPeb = PsGetProcessPeb(pProcess);
			if (!pPeb)
			{
				DPRINT("ffgame: %s: No PEB present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			for (INT i = 0; !pPeb->Ldr && i < 10; i++)
			{
				DPRINT("ffgame: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			if (!pPeb->Ldr)
			{
				DPRINT("ffgame: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
				pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
				pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
					return pEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("ffgame: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	return NULL;
}

NTSTATUS FFLookupProcessThread(IN HANDLE pid, OUT PETHREAD* ppThread)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID pBuf = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, 0);
	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuf;

	ASSERT(ppThread != NULL);
	if (ppThread == NULL)
		return STATUS_INVALID_PARAMETER;

	if (!pInfo)
	{
		DPRINT("ffgame: %s: Failed to allocate memory for process list\n", __FUNCTION__);
		return STATUS_NO_MEMORY;
	}

	Status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(pBuf, 0);
		return Status;
	}

	if (NT_SUCCESS(Status))
	{
		Status = STATUS_NOT_FOUND;
		for (;;)
		{
			if (pInfo->UniqueProcessId == pid)
			{
				Status = STATUS_SUCCESS;
				break;
			}
			else if (pInfo->NextEntryOffset)
				pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
			else
				break;
		}
	}

	if (NT_SUCCESS(Status))
	{
		Status = STATUS_NOT_FOUND;
		DPRINT("ffgame: %s: number of threads=%d\n", __FUNCTION__, pInfo->NumberOfThreads);
		for (ULONG i = 0; i < pInfo->NumberOfThreads; i++)
		{
			DPRINT("ffgame: %s: current threadId=%d\n", __FUNCTION__, pInfo->Threads[i].ClientId);
			if (pInfo->Threads[i].ClientId.UniqueThread == pid)
			{
				continue;
			}
			Status = PsLookupThreadByThreadId(pInfo->Threads[i].ClientId.UniqueThread, ppThread);
			break;
		}
	}
	else
		DPRINT("ffgame: %s: Failed to locate process\n", __FUNCTION__);

	if (pBuf)
		ExFreePoolWithTag(pBuf, 0);

	return Status;
}

HANDLE FFLookupProcessId(PWCHAR ProcessName)
{
	HANDLE ProcessId = 0;
	PVOID SysInfo;
	ULONG Size = 0x1000;
	NTSTATUS Status;
	UNICODE_STRING NeededName;

	do
	{
		SysInfo = ExAllocatePool(NonPagedPool, Size);
		if (!SysInfo) 
			return ProcessId;

		Status = ZwQuerySystemInformation(SystemProcessInformation, SysInfo, Size, NULL);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(SysInfo);
			Size *= 2;
		}
		else if (!NT_SUCCESS(Status))
		{
			goto exit;
		}
	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	RtlInitUnicodeString(&NeededName, ProcessName);

	PSYSTEM_PROCESS_INFORMATION pProcess = (PSYSTEM_PROCESS_INFORMATION)SysInfo;
	for (;;)
	{
		if (RtlEqualUnicodeString(&NeededName, &pProcess->ImageName, TRUE))
		{
			ProcessId = pProcess->UniqueProcessId;
			break;
		}

		if (!pProcess->NextEntryOffset) 
			break;

		pProcess = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcess + pProcess->NextEntryOffset);
	}

exit:
	ExFreePool(SysInfo);

	return ProcessId;
}

VOID FFAPCKernelRoutine(PKAPC pkaApc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* FirstArgument, PVOID* SecondArgument)
{
	DPRINT("ffgame: %s: Delivering apc \n", __FUNCTION__);

	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	if (PsGetCurrentProcessWow64Process() != NULL)
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);

	ExFreePool(pkaApc);
}


NTSTATUS FFDllInject(HANDLE hProcessID, PWCHAR dllPath, PKTHREAD pktThread)
{
	NTSTATUS Status = STATUS_NO_MEMORY;
	PEPROCESS pProcess;
	HANDLE hProcess;
	CLIENT_ID cidProcess;
	OBJECT_ATTRIBUTES attr = { sizeof(OBJECT_ATTRIBUTES), 0, NULL, OBJ_CASE_INSENSITIVE };
	PVOID pvMemory = 0;
	DWORD dwSize = 0x200;

	cidProcess.UniqueProcess = hProcessID;
	cidProcess.UniqueThread = 0;

	Status = PsLookupProcessByProcessId(hProcessID, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed\n", __FUNCTION__);
		goto exit;
	}

	if (PsIsProtectedProcess(pProcess))
	{
		DPRINT("ffgame: %s: process is protected\n", __FUNCTION__);
	}

	Status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &attr, &cidProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: ZwOpenProcess failed\n", __FUNCTION__);
		goto exit;
	}

	Status = ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: ZwAllocateVirtualMemory failed\n", __FUNCTION__);
		goto exit;
	}

	PKAPC pkaApc;
	PVOID pNtdll;
	PVOID pLdrDll;

	try 
	{
		PEPROCESS CurrentProcess = PsGetCurrentProcess();
		KAPC_STATE kasState;
		UNICODE_STRING uDllPath;
		UNICODE_STRING uNtDll;

		KeStackAttachProcess((PKPROCESS)pProcess, &kasState);
		
		RtlInitUnicodeString(&uDllPath, dllPath);
		RtlInitUnicodeString(&uNtDll, L"ntdll.dll");

		pNtdll = FFGetUserModule(pProcess, "ntdll.dll", TRUE);
		if (!pNtdll)
		{
			DPRINT("ffgame: %s: pNtdll not found\n", __FUNCTION__);
			Status = STATUS_NOT_FOUND;
		}

		pLdrDll = FFGetModuleFunction(pNtdll, "LdrLoadDll", pProcess, NULL);
		if (!pLdrDll)
		{
			DPRINT("ffgame: %s: pLdrDll not found\n", __FUNCTION__);
			Status = STATUS_NOT_FOUND;
		}
		
		
		if (NT_SUCCESS(Status))
		{
			pkaApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (pkaApc)
			{
				KeInitializeApc(pkaApc, pktThread, 0, (PKKERNEL_ROUTINE)FFAPCKernelRoutine, 0, (PKNORMAL_ROUTINE)(ULONG_PTR)pInject, UserMode, pvMemory);
				KeInsertQueueApc(pkaApc, 0, 0, IO_NO_INCREMENT);
				Status = STATUS_SUCCESS;
			}
		}

		KeUnstackDetachProcess(&kasState);
	}
	except(EXCEPTION_EXECUTE_HANDLER) 
	{
		DPRINT("ffgame: %s: exception\n", __FUNCTION__);
	}

exit:
	if (hProcess)
		ZwClose(hProcess);

	return Status;
}

NTSTATUS FFGameCpyMem(IN PCOPY_MEMORY pCopy)
{
	DPRINT("ffgame: %s: pid=%d, targetPtr=0x%08x -> localPtr=0x%X\n", __FUNCTION__, pCopy->TargetProcessId, pCopy->LocalPtr, pCopy->TargetPtr);

	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	Status = PsLookupProcessByProcessId((HANDLE)pCopy->TargetProcessId, &pProcess);

	if (NT_SUCCESS(Status))
	{
		SIZE_T bytes = 0;
		if (pCopy->Write != FALSE)
		{
			pSourceProc = PsGetCurrentProcess();
			pTargetProc = pProcess;
			pSource = (PVOID)pCopy->LocalPtr;
			pTarget = (PVOID)pCopy->TargetPtr;
		}
		else
		{
			pSourceProc = pProcess;
			pTargetProc = PsGetCurrentProcess();
			pSource = (PVOID)pCopy->TargetPtr;
			pTarget = (PVOID)pCopy->LocalPtr;
		}

		Status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->PtrSize, KernelMode, &bytes);
	}
	else
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, Status);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}

NTSTATUS FFInjectDll(IN PINJECT_DLL pInject)
{
	DPRINT("ffgame: %s: looking for process %ls\n", __FUNCTION__, pInject->ProcessName);

	NTSTATUS Status;
	HANDLE ProcessId = FFLookupProcessId(pInject->ProcessName);
	if (!ProcessId)
	{
		DPRINT("ffgame: %s: FFLookupProcessId failed\n", __FUNCTION__);
		Status = STATUS_NOT_FOUND;
		goto exit;
	}

	PETHREAD pThread;
	Status = FFLookupProcessThread(ProcessId, &pThread);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: FFLookupProcessThread failed\n", __FUNCTION__);
		goto exit;
	}
	
	Status = FFDllInject(ProcessId, pInject->FullDllPath, pThread);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: FFDllInject failed\n", __FUNCTION__);
		goto exit;
	}
	
exit:
	return Status;
}
