#pragma once

#include "FFGameDef.h"
#include "FFGameStruct.h"
#include "FFGameNative.h"

NTSTATUS FFCopyMemory(IN PCOPY_MEMORY pCopy);
NTSTATUS FFInjectDll(IN PINJECT_DLL pInject);