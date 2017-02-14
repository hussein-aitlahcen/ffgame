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
        private const string DSE = "dsefix.exe";
        private const string DRIVER = "0xFFGame.Drived.sys";
        private const string HOST = "0xFFGame.Host.dll";
        private const string MANAGED = "0xFFGame.ManagedHost.dll";

        static void Main(string[] args)
        {
            Process.Start(DSE);
            using (var ffgame = new FFGameDriver(Path.GetFullPath(DRIVER)))
            {
                var process = Process.GetProcesses().First(p => args.Contains(p.ProcessName));
                File.Copy(Path.GetFullPath(MANAGED),
                    Path.Combine(Path.GetDirectoryName(process.MainModule.FileName), MANAGED), true);
                ffgame.InjectDll(new InjectDll((uint)process.Id, Path.GetFullPath(HOST)));
            }
        }
    }
}
