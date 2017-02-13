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
	PINJECT_BUFFER pInjectBuffer = NULL;
	SIZE_T AllocateSize = PAGE_SIZE;
	LARGE_INTEGER Interval =
	{
		.QuadPart = -10 * 50
	};

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
		Status = FFAllocate(ZwCurrentProcess(), &pInjectBuffer, &AllocateSize);
		if (NT_ERROR(Status))
		{
			DPRINT("ffgame: %s: FFAllocate failed 0x%X\n", __FUNCTION__, Status);
			goto cleanup;
		}

		pInjectBuffer->pLdrLoadDll = pLdrLoadDll;
		pInjectBuffer->pFlags = NULL;
		pInjectBuffer->pPathToFile = NULL;
		pInjectBuffer->pModuleHandle = &pInjectBuffer->ModuleHandle;
		pInjectBuffer->pModuleFileName = &pInjectBuffer->ModuleFileName;
	
		pInjectBuffer->ModuleFileName.Buffer = (PWCHAR)&pInjectBuffer->FullDllPath;
		pInjectBuffer->ModuleFileName.MaximumLength = uInjectDllPath.MaximumLength;
		pInjectBuffer->ModuleFileName.Length = uInjectDllPath.Length;

		memcpy((PVOID)pInjectBuffer->FullDllPath, (PVOID)uInjectDllPath.Buffer, uInjectDllPath.Length);

		UCHAR ApcCode[] =
		{
			// prologue
			0x40, 0x53,				// push	 rbx
			0x48, 0x83, 0xEC, 0x20, // sub	 rsp, 32

			// call
			0x4C, 0x8B, 0x49, 0x20, // mov	 r9, QWORD PTR [rcx+32]
			0x48, 0x8B, 0xD9,		// mov	 rbx, rcx
			0x4C, 0x8B, 0x41, 0x18, // mov	 r8, QWORD PTR [rcx+24]
			0x48, 0x8B, 0x51, 0x10, // mov	 rdx, QWORD PTR [rcx+16]
			0x48, 0x8B, 0x49, 0x08, // mov	 rcx, QWORD PTR [rcx+8]
			0xFF, 0x13,				// call	 QWORD PTR [rbx]

			// call complete
			0xC7, 0x83, 0x40, 0x04, 0x00, 0x00, 0x7F, 0x1F, 0x3F, 0xCF, // mov	 DWORD PTR [rbx+1088], -817946753 ; CF3F1F7F

			// epilogue
			0x48, 0x83, 0xC4, 0x20, // add	 rsp, 32
			0x5B,					// pop	 rbx
			0xC3					// ret	 0
		};

		PVOID ApcCodeAddress = (PVOID)((ULONGLONG)pInjectBuffer + sizeof(INJECT_BUFFER));
		memcpy(ApcCodeAddress, &ApcCode, sizeof(ApcCode));

		DPRINT("ffgame: %s: apc param addres=0x%X\n", __FUNCTION__, pInjectBuffer);
		DPRINT("ffgame: %s: apc code addres=0x%X\n", __FUNCTION__, ApcCodeAddress);
		FFApcInject(pInject->hTargetProcess, ApcCodeAddress, (PVOID)(ULONGLONG)pInjectBuffer);

		SIZE_T i = 0;
		while (pInjectBuffer->Complete != CALL_COMPLETE && i < 400)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &Interval);
			i++;
		}

		DPRINT("ffgame: %s: Call complete\n", __FUNCTION__, pInjectBuffer);
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