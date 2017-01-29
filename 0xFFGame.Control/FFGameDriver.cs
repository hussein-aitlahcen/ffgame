using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace _0xFFGame.Control
{
    /*
    typedef struct _copy_memory_t
    {
        ULONGLONG LocalPtr;
        ULONGLONG TargetPtr;
        ULONGLONG PtrSize;
        ULONG TargetProcessId;
        BOOLEAN Write;
    }
    COPY_MEMORY, * PCOPY_MEMORY;

    typedef struct _inject_dll_t
    {
        WCHAR ProcessName[64];
        WCHAR FullDllPath[512];
    }
    INJECT_DLL, * PINJECT_DLL;
    */

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct CopyMemory
    {
        public readonly ulong LocalBuffer;         
        public readonly ulong TargetPointer; 
        public readonly ulong Size;             
        public readonly uint TargetProcessId;
        public readonly byte Write;       
        public CopyMemory(ulong local, ulong remote, ulong size, uint pid, bool write)
        {
            LocalBuffer = local;
            TargetPointer = remote;
            Size = size;
            TargetProcessId = pid;
            Write = (byte)(write ? 0x01 : 0x00);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public unsafe struct InjectDll
    {
        public readonly ulong ProcessId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public readonly string FullDllPath;
        public InjectDll(uint pId, string dllPath)
        {
            ProcessId = pId;
            FullDllPath = dllPath;
        }
    }


    public enum FFGameFunction
    {
        CopyMemory = 0x801,
        InjectDll = 0x802
    }

    public sealed class FFGameDriver : AbstractDeviceDriver
    {
        private static long FILE_DEVICE_FFGAME = 0x8888;
        private static string DRIVER_NAME = "ffgame";

        public FFGameDriver(string path) : base(FILE_DEVICE_FFGAME, DRIVER_NAME, path)
        {
        }

        public void InjectDll(InjectDll input)
        {
            FFGameDeviceIoControl(FFGameFunction.InjectDll, input);
        }

        public void CopyMemory(CopyMemory input)
        {
            FFGameDeviceIoControl(FFGameFunction.CopyMemory, input);
        }

        private void FFGameDeviceIoControl<T>(FFGameFunction fun, T input)
        {
            DeviceIoControl((long) fun, input);
        }
    }
}
