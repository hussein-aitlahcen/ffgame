#pragma once

#include "FFGameDef.h"

NTSTATUS FFAttachProcess(IN HANDLE hTargetProcess, OUT PEPROCESS* pProcess, OUT PKAPC_STATE pKApcState);
VOID FFDetachProcess(IN PKAPC_STATE pKApcState);
NTSTATUS FFFindModuleBase(IN HANDLE hTargetProcess, IN PUNICODE_STRING pModuleName, OUT PVOID* pModuleBase);