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
    public sealed class WinDriver : IDisposable
    {
        string driverName;
        string execPath;
        IntPtr fileHandle;

        public WinDriver(string driver, string driverExecPath)
        {
            this.driverName = driver;
            this.execPath = driverExecPath;
        }

        ~WinDriver()
        {
            // BUG - should never rely on finalizer to clean-up unmanaged resources 
            Dispose();
        }

        private void CloseStuff()
        {
            if (fileHandle != INVALID_HANDLE_VALUE)
            {
                fileHandle = INVALID_HANDLE_VALUE;
                CloseHandle(fileHandle);
            }
        }

        public void Dispose()
        {
            CloseStuff();
            GC.SuppressFinalize(this);
        }

        private readonly static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private const int SC_MANAGER_CONNECT = 0x0001;
        private const int SC_MANAGER_CREATE_SERVICE = 0x0002;
        private const int SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        private const int SC_MANAGER_LOCK = 0x0008;
        private const int SC_MANAGER_QUERY_LOCK_STATUS = 0x0010;
        private const int SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020;

        private const int SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                                                  SC_MANAGER_CONNECT |
                                                  SC_MANAGER_CREATE_SERVICE |
                                                  SC_MANAGER_ENUMERATE_SERVICE |
                                                  SC_MANAGER_LOCK |
                                                  SC_MANAGER_QUERY_LOCK_STATUS |
                                                  SC_MANAGER_MODIFY_BOOT_CONFIG;

        private const int SERVICE_QUERY_CONFIG = 0x0001;
        private const int SERVICE_CHANGE_CONFIG = 0x0002;
        private const int SERVICE_QUERY_STATUS = 0x0004;
        private const int SERVICE_ENUMERATE_DEPENDENTS = 0x0008;
        private const int SERVICE_START = 0x0010;
        private const int SERVICE_STOP = 0x0020;
        private const int SERVICE_PAUSE_CONTINUE = 0x0040;
        private const int SERVICE_INTERROGATE = 0x0080;
        private const int SERVICE_USER_DEFINED_CONTROL = 0x0100;

        private const int SERVICE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                                               SERVICE_QUERY_CONFIG |
                                               SERVICE_CHANGE_CONFIG |
                                               SERVICE_QUERY_STATUS |
                                               SERVICE_ENUMERATE_DEPENDENTS |
                                               SERVICE_START |
                                               SERVICE_STOP |
                                               SERVICE_PAUSE_CONTINUE |
                                               SERVICE_INTERROGATE |
                                               SERVICE_USER_DEFINED_CONTROL;

        private const int SERVICE_DEMAND_START = 0x00000003;
        private const int SERVICE_KERNEL_DRIVER = 0x00000001;
        private const int SERVICE_ERROR_NORMAL = 0x00000001;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint OPEN_EXISTING = 3;
        private const uint IOCTL_SHOCKMGR_READ_ACCELEROMETER_DATA = 0x733fc;
        private const int FACILITY_WIN32 = unchecked((int) 0x80070000);
        private IntPtr handle = INVALID_HANDLE_VALUE;

        [DllImport("advapi32", SetLastError = true)]
        internal static extern IntPtr OpenSCManager(string machineName, string
            databaseName, uint dwDesiredAccess);

        [DllImport("advapi32", SetLastError = true)]
        internal static extern IntPtr CreateService(IntPtr hSCManager, string
                serviceName, string displayName,
            uint dwDesiredAccess, uint serviceType, uint startType, uint
                errorControl,
            string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId,
            string lpDependencies,
            string lpServiceStartName, string lpPassword);

        [DllImport("advapi32")]
        internal static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern IntPtr CreateFile(string lpFileName,
            [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
            [MarshalAs(UnmanagedType.U4)] System.IO.FileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32")]
        internal static extern void CloseHandle(IntPtr handle);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint
                dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer,
            uint nOutBufferSize, ref uint lpBytesReturned, IntPtr lpOverlapped);

        internal bool LoadDeviceDriver()
        {
            IntPtr scHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scHandle != INVALID_HANDLE_VALUE)
            {
                IntPtr hService = CreateService(scHandle, this.driverName,
                    this.driverName, SERVICE_ALL_ACCESS
                    , SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL
                    , execPath, null, null, null, null, null);
                if (hService != IntPtr.Zero)
                {
                    CloseServiceHandle(hService); // close both handles 
                    CloseServiceHandle(scHandle);
                    // Start the driver using System.Management (WMI) 
                    if (ExecuteSCMOperationOnDriver(this.driverName, "StartService") == 0)
                        return true;
                }
                else if (Marshal.GetLastWin32Error() == 1073) // Driver/Service already in DB 
                {
                    CloseServiceHandle(scHandle);
                    // Start the driver using System.Management (WMI) 
                    if (ExecuteSCMOperationOnDriver(this.driverName, "StartService") == 0)
                        return true;
                }
                Marshal.ThrowExceptionForHR(HRESULT_FROM_WIN32(Marshal.GetLastWin32Error()));
            }
            return false;
        }

        internal bool UnloadDeviceDriver()
        {
            int ret = 0;
            if (fileHandle != IntPtr.Zero && fileHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(fileHandle);
            }
            if ((ret = ExecuteSCMOperationOnDriver(driverName, "StopService")) == 0)
            {
                ret = ExecuteSCMOperationOnDriver(driverName, "Delete");
            }
            if (ret != 0)
            {
                return false;
            }
            return true;
        }

        private static int ExecuteSCMOperationOnDriver(string driverName, string
            operation)
        {
            ManagementPath path = new ManagementPath();
            path.Server = ".";
            path.NamespacePath = @"root\CIMV2";
            path.RelativePath = @"Win32_BaseService.Name='" + driverName + "'";
            using (ManagementObject o = new ManagementObject(path))
            {
                ManagementBaseObject outParams = o.InvokeMethod(operation,
                    null, null);
                return Convert.ToInt32(outParams.Properties["ReturnValue"].Value);
            }
        }

        internal IntPtr OpenDevice()
        {
            fileHandle = CreateFile("\\\\.\\" + driverName, FileAccess.ReadWrite, 
                FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0,
                IntPtr.Zero);
            if (handle == INVALID_HANDLE_VALUE)
            {
                Marshal.ThrowExceptionForHR(HRESULT_FROM_WIN32(Marshal.GetLastWin32Error()));
            }
            return fileHandle;
        }

        private static int HRESULT_FROM_WIN32(int x)
        {
            return x <= 0 ? x : ((x & 0x0000FFFF) | FACILITY_WIN32);
        }
    }

    class Program
    {
        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DeviceIoControl(
           IntPtr hDevice,
           uint dwIoControlCode,
           ref CopyMemory input,
           int nInBufferSize,
           out CopyMemory output,
           int nOutBufferSize,
           out int pBytesReturned,
           IntPtr overlapped);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
        public unsafe struct CopyMemory
        {
            public ulong LocalBuffer;         // Buffer address
            public ulong TargetPointer;        // Target address
            public ulong Size;             // Buffer size
            public uint PID;              // Target process id
            public byte Write;            // TRUE if write operation, FALSE if read
            public CopyMemory(ulong local, ulong remote, ulong size, uint pid, bool write)
            {
                LocalBuffer = local;
                TargetPointer = remote;
                Size = size;
                PID = pid;
                Write = (byte)(write ? 0x01 : 0x00);
            }
        }
            
        public enum FFGameFunction
        {
            CopyMemory = 0x801
        }

        private static int FILE_DEVICE_FFGAME = 0x8888;
        private static int FILE_ACCESS = 0x0001 | 0x0002;
        private static int METHOD = 0x00;

        public static IOControlCode ControlCode(FFGameFunction fun)
        {
            return (IOControlCode)(uint) ((FILE_DEVICE_FFGAME << 16) | ((FILE_ACCESS) << 14) | ((int) fun << 2) | METHOD);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct Test
        {
            public int x;
            public int y;
            public int z;
        }

        static unsafe void Main(string[] args)
        {
            WinDriver driver = new WinDriver("ffgame", @"C:\\Users\\Hussein\\Documents\\visual studio 2015\\Projects\\0xFFGame\\x64\\Release\\0xFFGame.Drived.sys");
            if (driver.LoadDeviceDriver())
            {
                IntPtr handle = driver.OpenDevice();
                // use device using ....DeviceIoControl(handle,....) see class code for 
                var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Test>());
                var target = Marshal.AllocHGlobal(Marshal.SizeOf<Test>());
                Marshal.StructureToPtr(new Test
                {
                    x = 5,
                    y = 2,
                    z = 10
                }, target, true);

                var pid = Process.GetCurrentProcess().Id;
                var input = new CopyMemory((ulong) pointer, (ulong)target, (ulong)Marshal.SizeOf<Test>(), (uint) pid, false);
                DeviceIoControlHelper.InvokeIoControl(new SafeFileHandle(handle, false),
                        ControlCode(FFGameFunction.CopyMemory), input);
                var y = Marshal.PtrToStructure<Test>(pointer);
            }
            //unload when done 
            driver.UnloadDeviceDriver();
            driver.Dispose();
        }
    }
}
