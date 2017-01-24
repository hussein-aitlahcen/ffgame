#include "FFGameFunc.h"

NTSTATUS FFGameCpyMem(IN PCOPY_MEMORY pCopy)
{
	DPRINT("ffgame: %s: pid=%d, targetPtr=0x%08x -> localPtr=0x%08x", __FUNCTION__, pCopy->TargetProcessId, pCopy->LocalPtr, pCopy->TargetPtr);

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


HANDLE GetPidAndTidByName(PWCHAR ProcessName, PHANDLE pThreadId)
{
	HANDLE Ret = 0;
	PVOID SysInfo;
	ULONG Size = 0x1000;
	NTSTATUS St;
	UNICODE_STRING NeededName;

	do
	{
		SysInfo = ExAllocatePool(NonPagedPool, Size);
		if (!SysInfo) return Ret;

		St = ZwQuerySystemInformation(SystemProcessInformation, SysInfo, Size, NULL);
		if (St == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(SysInfo);
			Size *= 2;
		}
		else if (!NT_SUCCESS(St))
		{
			ExFreePool(SysInfo);
			return Ret;
		}
	} while (St == STATUS_INFO_LENGTH_MISMATCH);

	RtlInitUnicodeString(&NeededName, ProcessName);

	PSYSTEM_PROCESS_INFORMATION pProcess = (PSYSTEM_PROCESS_INFORMATION)SysInfo;
	for (;;)
	{
		if (RtlEqualUnicodeString(&NeededName, &pProcess->ImageName, TRUE))
		{
			Ret = pProcess->ProcessId;
			*pThreadId = pProcess->Threads[0].ClientId.UniqueThread;

			break;
		}

		if (!pProcess->NextEntryOffset) break;

		pProcess = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcess + pProcess->NextEntryOffset);
	}

	ExFreePool(SysInfo);

	return Ret;
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

	Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &Info, sizeof(Info), &Length);
	if (NT_SUCCESS(Status))
	{
		UNICODE_STRING uStr;
		PPEB Peb = Info.PebBaseAddress;

		RtlInitUnicodeString(&uStr, ModuleName);

		LIST_ENTRY* head = &Peb->LoaderData->InLoadOrderModuleList;
		for (LIST_ENTRY* entry = head->Flink; entry != head; entry = entry->Flink)
		{
			LDR_DATA_TABLE_ENTRY* ldr_entry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

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
	ExFreePool(pkaApc);
}

NTSTATUS DllInject(HANDLE hProcessID, PEPROCESS pepProcess, PKTHREAD pktThread)
{
	HANDLE hProcess;
	OBJECT_ATTRIBUTES oaAttributes = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID cidProcess;
	PVOID pvMemory = 0;
	DWORD dwSize = 0x1000;

	cidProcess.UniqueProcess = hProcessID;
	cidProcess.UniqueThread = 0;
	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oaAttributes, &cidProcess)))
	{
		if (NT_SUCCESS(ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
		{
			KAPC_STATE kasState;
			PKAPC pkaApc;
			PVOID FunctionAddress;

			KeStackAttachProcess((PKPROCESS)pepProcess, &kasState);

			FunctionAddress = GetProcAddressInModule(L"kernel32.dll", "LoadLibraryExW");
			if (!FunctionAddress) 
				DPRINT("ffgame: %s: GetProcAddress failed\n", __FUNCTION__);

			wcscpy((PWCHAR)pvMemory, "");

			KeUnstackDetachProcess(&kasState);

			pkaApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (pkaApc)
			{
				KeInitializeApc(pkaApc, pktThread, 0, (PKKERNEL_ROUTINE)APCKernelRoutine, 0, (PKNORMAL_ROUTINE)FunctionAddress, UserMode, pvMemory);
				KeInsertQueueApc(pkaApc, 0, 0, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
		}
		else
		{
			DPRINT("ffgame: %s: ZwAllocVirtualMemory failed\n", __FUNCTION__);
		}

		ZwClose(hProcess);
	}
	else
	{
		DPRINT("ffgame: %s: ZwOpenProcess failed\n", __FUNCTION__);
	}

	return STATUS_NO_MEMORY;
}

typedef struct _WI_INJECT
{
	PKTHREAD pktThread;
	PEPROCESS pepProcess;
	HANDLE hProcessID;
	KEVENT keEvent;
	WORK_QUEUE_ITEM qiItem;
} WI_INJECT, *PWI_INJECT;

VOID InjectorWorkItem(PVOID pvContext)
{
	NTSTATUS Status = DllInject(((PWI_INJECT)pvContext)->hProcessID, ((PWI_INJECT)pvContext)->pepProcess, ((PWI_INJECT)pvContext)->pktThread);
	if (NT_SUCCESS(Status))
	{
		DPRINT("ffgame %s: ");
	}
	else
	{
		DbgPrint("NO\n");
	}
	KeSetEvent(&((PWI_INJECT)pvContext)->keEvent, (KPRIORITY)0, FALSE);
}

VOID APCInjectRoutine(PKAPC pkaApc, PKNORMAL_ROUTINE* u1, PVOID* u2, PVOID* u3, PVOID* u4)
{
	ExFreePool(pkaApc);

	WI_INJECT wiiItem;

	wiiItem.pktThread = KeGetCurrentThread();
	wiiItem.pepProcess = IoGetCurrentProcess();
	wiiItem.hProcessID = PsGetCurrentProcessId();

	KeInitializeEvent(&wiiItem.keEvent, NotificationEvent, FALSE);

	ExInitializeWorkItem(&wiiItem.qiItem, InjectorWorkItem, &wiiItem);
	ExQueueWorkItem(&wiiItem.qiItem, DelayedWorkQueue);

	//was KernelMode not work do UserMode and work
	KeWaitForSingleObject(&wiiItem.keEvent, Executive, UserMode, TRUE, 0);

	return;
}

NTSTATUS FFInjectDll(IN PINJECT_DLL pInject)
{
	NTSTATUS Status;
	HANDLE ThreadId;
	HANDLE ProcessId = GetPidAndTidByName(pInject->ProcessName, &ThreadId);
	if (ProcessId)
	{
		PETHREAD Thread;
		Status = PsLookupThreadByThreadId(ThreadId, &Thread);
		if (NT_SUCCESS(Status))
		{
			PKAPC pkaApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (pkaApc)
			{
				Status = KeInitializeApc(pkaApc, (PKTHREAD)Thread, 0, APCInjectRoutine, 0, 0, KernelMode, 0);
				if (NT_SUCCESS(Status))
				{
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
			ObDereferenceObject(Thread);
		}
		else
		{
			DPRINT("ffgame: %s: PsLookupThreadByThreadId failed\n", __FUNCTION__);
		}
	}
	else
	{
		DPRINT("ffgame: %s: GetPidAndTidByName failed\n", __FUNCTION__);
	}
	return Status;
}
