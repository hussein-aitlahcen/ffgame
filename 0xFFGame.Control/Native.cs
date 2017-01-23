using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace _0xFFGame.Control
{
    public static class Native
    {
        internal readonly static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        internal const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        internal const int SC_MANAGER_CONNECT = 0x0001;
        internal const int SC_MANAGER_CREATE_SERVICE = 0x0002;
        internal const int SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        internal const int SC_MANAGER_LOCK = 0x0008;
        internal const int SC_MANAGER_QUERY_LOCK_STATUS = 0x0010;
        internal const int SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020;

        internal const int SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                                                  SC_MANAGER_CONNECT |
                                                  SC_MANAGER_CREATE_SERVICE |
                                                  SC_MANAGER_ENUMERATE_SERVICE |
                                                  SC_MANAGER_LOCK |
                                                  SC_MANAGER_QUERY_LOCK_STATUS |
                                                  SC_MANAGER_MODIFY_BOOT_CONFIG;

        internal const int SERVICE_QUERY_CONFIG = 0x0001;
        internal const int SERVICE_CHANGE_CONFIG = 0x0002;
        internal const int SERVICE_QUERY_STATUS = 0x0004;
        internal const int SERVICE_ENUMERATE_DEPENDENTS = 0x0008;
        internal const int SERVICE_START = 0x0010;
        internal const int SERVICE_STOP = 0x0020;
        internal const int SERVICE_PAUSE_CONTINUE = 0x0040;
        internal const int SERVICE_INTERROGATE = 0x0080;
        internal const int SERVICE_USER_DEFINED_CONTROL = 0x0100;

        internal const int SERVICE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                                               SERVICE_QUERY_CONFIG |
                                               SERVICE_CHANGE_CONFIG |
                                               SERVICE_QUERY_STATUS |
                                               SERVICE_ENUMERATE_DEPENDENTS |
                                               SERVICE_START |
                                               SERVICE_STOP |
                                               SERVICE_PAUSE_CONTINUE |
                                               SERVICE_INTERROGATE |
                                               SERVICE_USER_DEFINED_CONTROL;

        internal const int SERVICE_DEMAND_START = 0x00000003;
        internal const int SERVICE_KERNEL_DRIVER = 0x00000001;
        internal const int SERVICE_ERROR_NORMAL = 0x00000001;
        internal const int FACILITY_WIN32 = unchecked((int)0x80070000);

        [DllImport("advapi32", SetLastError = true)]
        internal static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwDesiredAccess);

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
    }
}
