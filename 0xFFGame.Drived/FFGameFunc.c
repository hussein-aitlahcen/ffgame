#include "FFGameFunc.h"

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

PVOID GetProcedureAddressByHash(PVOID pvBase, PCHAR Name)
{
	PIMAGE_NT_HEADERS pImgNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pImgDirExport;
	PDWORD pdwNames;
	PDWORD pdwProcedures;
	PWORD pdwOrdinals;
	DWORD i;
	pImgNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)(((PIMAGE_DOS_HEADER)pvBase)->e_lfanew) + (DWORD_PTR)pvBase);
	pImgDirExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)(pImgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + (DWORD_PTR)pvBase);
	pdwNames = MAKE_PTR(pvBase, pImgDirExport->AddressOfNames, PDWORD);
	pdwProcedures = MAKE_PTR(pvBase, pImgDirExport->AddressOfFunctions, PDWORD);
	pdwOrdinals = MAKE_PTR(pvBase, pImgDirExport->AddressOfNameOrdinals, PWORD);
	for (i = 0; i < pImgDirExport->NumberOfNames; i++)
	{
		if (!strcmp(MAKE_PTR(pvBase, pdwNames[i], PCHAR), Name))
		{
			return MAKE_PTR(pvBase, pdwProcedures[pdwOrdinals[i]], PVOID);
		}
	}
	return NULL;
}

PVOID GetProcAddressInModule(PWCHAR ModuleName, PCHAR FunctionName)
{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION Info;
	PVOID pModuleBase = NULL;
	PVOID pProcAddress = NULL;
	ULONG Length;

	Status = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, &Info, sizeof(Info), &Length);
	if (NT_SUCCESS(Status))
	{
		UNICODE_STRING uStr;
		PPEB Peb = Info.PebBaseAddress;

		RtlInitUnicodeString(&uStr, ModuleName);

		LIST_ENTRY* head = &Peb->LoaderData->InLoadOrderModuleList;
		for (LIST_ENTRY* entry = head->Flink; entry != head; entry = entry->Flink)
		{
			LDR_DATA_TABLE_ENTRY* ldr_entry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			DPRINT("ffgame: %s: checking module %ls=%ls\n", __FUNCTION__, ldr_entry->BaseDllName.Buffer, uStr.Buffer);

			if (RtlEqualUnicodeString(&ldr_entry->BaseDllName, &uStr, TRUE))
			{
				pModuleBase = ldr_entry->DllBase;

				break;
			}
		}
	}
	if (pModuleBase)
	{
		pProcAddress = GetProcedureAddressByHash(pModuleBase, FunctionName);
	}
	else
	{
		DPRINT("ffgame: %s: pModuleBase\n", __FUNCTION__);
	}
	return pProcAddress;
}

VOID APCKernelRoutine(PKAPC pkaApc, PKNORMAL_ROUTINE* u1, PVOID* u2, PVOID* ppvMemory, PVOID* u3)
{
	DPRINT("ffgame: %s: apc delivered\n", __FUNCTION__);
	ExFreePool(pkaApc);
}


NTSTATUS DllInject(HANDLE hProcessID, PWCHAR dllPath, PEPROCESS pepProcess, PKTHREAD pktThread)
{
	NTSTATUS Status = STATUS_NO_MEMORY;
	HANDLE hProcess;
	CLIENT_ID cidProcess;
	OBJECT_ATTRIBUTES attr = { sizeof(OBJECT_ATTRIBUTES), 0, NULL, OBJ_CASE_INSENSITIVE };
	PVOID pvMemory = 0;
	DWORD dwSize = 0x1000;

	cidProcess.UniqueProcess = hProcessID;
	cidProcess.UniqueThread = 0;

	if (PsIsProtectedProcess(pepProcess))
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
	PVOID FunctionAddress;

	try 
	{
		KAPC_STATE kasState;
		KeStackAttachProcess((PKPROCESS)pepProcess, &kasState);
		FunctionAddress = GetProcAddressInModule(L"kernel32.dll", "LoadLibraryA");
		if (!FunctionAddress)
			DPRINT("ffgame: %s: GetProcAddress failed\n", __FUNCTION__);

		wcscpy((PWCHAR)pvMemory, dllPath);

		KeUnstackDetachProcess(&kasState);

		pkaApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
		if (pkaApc)
		{
			KeInitializeApc(pkaApc, pktThread, 0, (PKKERNEL_ROUTINE)APCKernelRoutine, 0, (PKNORMAL_ROUTINE)FunctionAddress, UserMode, pvMemory);
			KeInsertQueueApc(pkaApc, 0, 0, IO_NO_INCREMENT);
			Status = STATUS_SUCCESS;
		}
	}
	except(EXCEPTION_EXECUTE_HANDLER) 
	{
		DPRINT("ffgame: %s: exception\n", __FUNCTION__);
	}

exit:
	return Status;
}

typedef struct _WI_INJECT
{
	PWCHAR pDllPath;
	PKTHREAD pktThread;
	PEPROCESS pepProcess;
	HANDLE hProcessID;
	KEVENT keEvent;
	WORK_QUEUE_ITEM qiItem;
} WI_INJECT, *PWI_INJECT;

VOID InjectorWorkItem(PVOID pvContext)
{
	PWI_INJECT pwInject = (PWI_INJECT)pvContext;

	NTSTATUS Status = DllInject(pwInject->hProcessID, pwInject->pDllPath, pwInject->pepProcess, pwInject->pktThread);
	if (NT_SUCCESS(Status))
	{
		DPRINT("ffgame: %s: sucessfully injected dll", __FUNCTION__);
	}
	else
	{
		DPRINT("ffgame: %s: failed to inject dll status=0x%x", __FUNCTION__, Status);
	}
	KeSetEvent(&((PWI_INJECT)pvContext)->keEvent, (KPRIORITY)0, FALSE);
}

VOID APCInjectRoutine(PKAPC pkaApc, PKNORMAL_ROUTINE* pNormalRoutine, PVOID* pNormalContext, PVOID* u3, PVOID* u4)
{
	ExFreePool(pkaApc);
	
	PINJECT_DLL pInject = (PINJECT_DLL)pNormalContext;

	WI_INJECT wiiItem;

	wiiItem.pktThread = KeGetCurrentThread();
	wiiItem.pepProcess = IoGetCurrentProcess();
	wiiItem.hProcessID = PsGetCurrentProcessId();
	wiiItem.pDllPath = pInject->FullDllPath;

	KeInitializeEvent(&wiiItem.keEvent, NotificationEvent, FALSE);

	ExInitializeWorkItem(&wiiItem.qiItem, InjectorWorkItem, &wiiItem);
	ExQueueWorkItem(&wiiItem.qiItem, DelayedWorkQueue);

	//was KernelMode not work do UserMode and work
	KeWaitForSingleObject(&wiiItem.keEvent, Executive, UserMode, TRUE, 0);

	return;
}

NTSTATUS FFInjectDll(IN PINJECT_DLL pInject)
{
	DPRINT("ffgame: %s: looking for process %ls\n", __FUNCTION__, pInject->ProcessName);

	NTSTATUS Status;
	HANDLE ProcessId = FFLookupProcessId(pInject->ProcessName);

	if (ProcessId)
	{
		PETHREAD pThread;
		Status = FFLookupProcessThread(ProcessId, &pThread);
		if (NT_SUCCESS(Status))
		{
			DPRINT("ffgame: %s: allocating apc\n", __FUNCTION__);
			PKAPC pkaApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (pkaApc)
			{
				DPRINT("ffgame: %s: initializing apc", __FUNCTION__);
				Status = KeInitializeApc(pkaApc, (PKTHREAD)pThread, 0, APCInjectRoutine, 0, 0, KernelMode, pInject);
				if (NT_SUCCESS(Status))
				{
					DPRINT("ffgame: %s: queueing apc", __FUNCTION__);
					Status = KeInsertQueueApc(pkaApc, 0, 0, IO_NO_INCREMENT);
					if (!NT_SUCCESS(Status))
					{
						DPRINT("ffgame: %s: KeInsertQueueApc failed\n", __FUNCTION__);
					}
				}
				else
				{
					DPRINT("ffgame: %s: KeInitializeApc failed\n", __FUNCTION__);
				}
			}
			else
			{
				DPRINT("ffgame: %s: ExAllocatePool failed\n", __FUNCTION__);
				Status = STATUS_FWP_NULL_POINTER;
			}
			ObDereferenceObject(pThread);
		}
		else
		{
			DPRINT("ffgame: %s: FFLookupProcessThread failed\n", __FUNCTION__);
		}
	}
	else
	{
		DPRINT("ffgame: %s: FFLookupProcessId failed\n", __FUNCTION__);
	}
	return Status;
}
