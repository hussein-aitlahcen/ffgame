#include "FFGameNative.h"

NTSTATUS FFAttachProcess(IN HANDLE hTargetProcess, OUT PEPROCESS* pProcess, OUT PKAPC_STATE pKApcState)
{
	NTSTATUS Status = STATUS_SUCCESS;

	Status = PsLookupProcessByProcessId(hTargetProcess, pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed\n", __FUNCTION__);
		goto cleanup;
	}

	KeStackAttachProcess(*pProcess, pKApcState);

cleanup:
	if (*pProcess)
		ObDereferenceObject(*pProcess);

	return Status;
}

VOID FFDetachProcess(IN PKAPC_STATE pKApcState)
{
	KeUnstackDetachProcess(pKApcState);
}

NTSTATUS FFFindModuleBase(IN HANDLE hTargetProcess, IN PUNICODE_STRING pModuleName, OUT PVOID* pModuleBase)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PPEB pProcessPEB = NULL;
	PLIST_ENTRY pEntryCurrent = NULL, pEntryEnd = NULL;
	PLDR_DATA_TABLE_ENTRY pEntryLdr = NULL;
	KAPC_STATE KApcState;

	Status = FFAttachProcess(hTargetProcess, &pProcess, &KApcState);
	if (NT_ERROR(Status))
	{
		goto cleanup;
	}

	pProcessPEB = PsGetProcessPeb(pProcess);
	if (!pProcessPEB)
	{
		DPRINT("ffgame: %s: PsGetProcessPeb failed\n", __FUNCTION__);
		goto detach;
	}

	DPRINT("ffgame: %s: finding %ls\n", __FUNCTION__, pModuleName->Buffer);

	pEntryCurrent = pEntryEnd = pProcessPEB->Ldr->InMemoryOrderModuleList.Flink;

	do
	{
		pEntryLdr = CONTAINING_RECORD(pEntryCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (RtlEqualUnicodeString(pModuleName, &pEntryLdr->BaseDllName, TRUE))
		{
			*pModuleBase = pEntryLdr->DllBase;
			DPRINT("ffgame: %s: found %ls, base address 0x%x\n", __FUNCTION__, pModuleName->Buffer, *pModuleBase);
		}
		pEntryCurrent = pEntryCurrent->Flink;
	} while (!(*pModuleBase) && pEntryCurrent != pEntryEnd);

detach:

	FFDetachProcess(&KApcState);

cleanup:

	return Status;
}