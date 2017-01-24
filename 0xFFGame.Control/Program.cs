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

        static void Main(string[] args)
        {
            using (var ffgame = new FFGameDriver(Path.GetFullPath("0xFFGame.Drived.sys")))
            {
                var processName = Marshal.StringToHGlobalUni("ETDCtrl.exe");
                var dllPath = Marshal.StringToHGlobalUni(Path.GetFullPath("0xFFGame.Host.dll"));
                ffgame.InjectDll(new InjectDll(processName, dllPath));
            }
        }
    }
}
