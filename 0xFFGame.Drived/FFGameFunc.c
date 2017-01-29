#include "FFGameFunc.h"

NTSTATUS FFCopyMemory(IN PCOPY_MEMORY pCopy)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	DPRINT("ffgame: %s: pid=%d, targetPtr=0x%08x -> localPtr=0x%X\n", __FUNCTION__, pCopy->hTargetProcess, pCopy->pLocalAddress, pCopy->pTargetAddress);

	Status = PsLookupProcessByProcessId(pCopy->hTargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: could not find target process\n", __FUNCTION__);
		goto cleanup;
	}

	SIZE_T bytes = 0;
	if (pCopy->Write)
	{
		pSourceProc = PsGetCurrentProcess();
		pTargetProc = pProcess;
		pSource = pCopy->pLocalAddress;
		pTarget = pCopy->pTargetAddress;
	}
	else
	{
		pSourceProc = pProcess;
		pTargetProc = PsGetCurrentProcess();
		pSource = pCopy->pTargetAddress;
		pTarget = pCopy->pLocalAddress;
	}

	Status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->Length, KernelMode, &bytes);

cleanup:
	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}

NTSTATUS FFInjectDll(IN PINJECT_DLL pInject)
{
	DPRINT("ffgame: %s: injecting %ls into processId %d\n", __FUNCTION__, pInject->pFullDllPath, pInject->hTargetProcess);

	NTSTATUS Status = STATUS_SUCCESS;
	PVOID pModuleBase = NULL;
	PLDR_LOADDLL pLdrLoadDll = 0;
	PEPROCESS pProcess = NULL;
	UNICODE_STRING uModuleName = RTL_CONSTANT_STRING(L"ntdll.dll");
	UNICODE_STRING uInjectDllPath;
	KAPC_STATE KApcState;
	BOOL Attached = FALSE;
	PLDR_LOAD_DLL_T pLdrLoadDllStruct = NULL;
	SIZE_T AllocateSize = PAGE_SIZE;

	RtlInitUnicodeString(&uInjectDllPath, pInject->pFullDllPath);

	Status = PsLookupProcessByProcessId(pInject->hTargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed\n", __FUNCTION__);
		goto cleanup;
	}

	if (!pProcess)
	{
		DPRINT("ffgame: %s: pProcess NULL failed\n", __FUNCTION__);
		goto cleanup;
	}

	KeStackAttachProcess(pProcess, &KApcState);
	Attached = TRUE;

	Status = FFFindModuleBase(pProcess, &uModuleName, &pModuleBase);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: FFFindModuleBase failed\n", __FUNCTION__);
		goto cleanup;
	}

	pLdrLoadDll = (PLDR_LOADDLL)FFFindModuleExport(pModuleBase, "LdrLoadDll");
	if (!pLdrLoadDll)
	{
		DPRINT("ffgame: %s: FFFindModuleExport failed\n", __FUNCTION__);
		goto cleanup;
	}

	try
	{
		Status = FFAllocate(&pLdrLoadDllStruct, &AllocateSize);
		if (NT_ERROR(Status))
		{
			DPRINT("ffgame: %s: FFAllocate failed 0x%X\n", __FUNCTION__, Status);
			goto cleanup;
		}

		pLdrLoadDllStruct->Flags = NULL;
		pLdrLoadDllStruct->PathToFile = NULL;
		pLdrLoadDllStruct->pModuleHandle = &pLdrLoadDllStruct->ModuleHandle;
		pLdrLoadDllStruct->pModuleFileName = &pLdrLoadDllStruct->ModuleFileName;
	
		pLdrLoadDllStruct->ModuleFileName.Buffer = (PWCHAR)&pLdrLoadDllStruct->FullDllPath;
		pLdrLoadDllStruct->ModuleFileName.MaximumLength = uInjectDllPath.MaximumLength;
		pLdrLoadDllStruct->ModuleFileName.Length = uInjectDllPath.Length;

		memcpy((PVOID)pLdrLoadDllStruct->FullDllPath, (PVOID)uInjectDllPath.Buffer, uInjectDllPath.Length);

		FFApcInject(pInject->hTargetProcess, (PVOID)pLdrLoadDll, (PVOID)pLdrLoadDllStruct);
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("ffgame: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

cleanup:
	if(Attached)
		KeUnstackDetachProcess(&KApcState);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}