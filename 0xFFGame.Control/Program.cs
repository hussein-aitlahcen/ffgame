using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DeviceIOControlLib.Objects.Enums;
using DeviceIOControlLib.Wrapper;
using Microsoft.Win32.SafeHandles;

namespace _0xFFGame.Control
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct Test
        {
            public int x;
            public int y;
            public int z;
        }

        static unsafe void Main(string[] args)
        {
            using (var ffgame = new FFGameDriver(Path.GetFullPath("0xFFGame.Drived.sys")))
            {
                if (ffgame.LoadDeviceDriver())
                {
                    ffgame.OpenDevice();
                    var pointer = Marshal.StringToHGlobalUni("Hello FFGame !");
                    var pid = Process.GetProcesses().First(p => p.ProcessName == "notepad").Id;
                    ffgame.CopyMemory(new CopyMemory((ulong)pointer, 0x04C9D90, 26,
                        (uint)pid, true));
                }
                ffgame.UnloadDeviceDriver();
            }
        }
    }
}
