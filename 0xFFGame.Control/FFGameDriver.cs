using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace _0xFFGame.Control
{
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

    public enum FFGameFunction
    {
        CopyMemory = 0x801
    }

    public sealed class FFGameDriver : AbstractDeviceDriver
    {
        private static long FILE_DEVICE_FFGAME = 0x8888;
        private static string DRIVER_NAME = "ffgame";

        public FFGameDriver(string path) : base(FILE_DEVICE_FFGAME, DRIVER_NAME, path)
        {
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
