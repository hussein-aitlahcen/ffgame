using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using DeviceIOControlLib.Objects.Enums;
using DeviceIOControlLib.Wrapper;
using Microsoft.Win32.SafeHandles;
using static _0xFFGame.Control.Native;

namespace _0xFFGame.Control
{
    public abstract class AbstractDeviceDriver : IDisposable
    {
        private static long FILE_ACCESS = 0x0001 | 0x0002;
        private static long METHOD = 0x00;

        public long FileDevice { get; }
        public string DriverName { get; }
        public string DriverPath { get; }

        private IntPtr m_fileHandle;

        protected AbstractDeviceDriver(long fileDevice, string name, string path)
        {
            FileDevice = fileDevice;
            DriverName = name;
            DriverPath = path;

            OpenDevice();
        }

        private long ControlCode(long functionId)
        {
            return FileDevice << 16 | FILE_ACCESS << 14 | functionId << 2 | METHOD;
        }


        ~AbstractDeviceDriver()
        {
            Dispose();
        }

        private bool LoadDeviceDriver()
        {
            var scHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scHandle == INVALID_HANDLE_VALUE)
                return false;

            var hService = CreateService(scHandle, DriverName,
                DriverName, SERVICE_ALL_ACCESS
                , SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL
                , DriverPath, null, null, null, null, null);

            // Create service
            if (hService != IntPtr.Zero)
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(scHandle);
                if (StartService() == 0)
                    return true;
            }
            // Skip creation if already created
            else if (Marshal.GetLastWin32Error() == 1073) 
            {
                CloseServiceHandle(scHandle);
                if (StartService() == 0)
                    return true;
            }

            Marshal.ThrowExceptionForHR(HRESULT_FROM_WIN32(Marshal.GetLastWin32Error()));

            return false;
        }

        private bool UnloadDeviceDriver()
        {
            var ret = 0;
            if (m_fileHandle != IntPtr.Zero && m_fileHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(m_fileHandle);
                m_fileHandle = IntPtr.Zero;
            }
            if ((ret = StopService()) == 0)
            {
                ret = DeleteService();
            }
            return ret == 0;
        }

        private int StartService()
        {
            return ExecuteSCMOperationOnDriver("StartService");
        }

        private int DeleteService()
        {
            return ExecuteSCMOperationOnDriver("Delete");
        }

        private int StopService()
        {
            return ExecuteSCMOperationOnDriver("StopService");
        }

        private int ExecuteSCMOperationOnDriver(string
            operation)
        {
            var path = new ManagementPath
            {
                Server = ".",
                NamespacePath = @"root\CIMV2",
                RelativePath = @"Win32_BaseService.Name='" + DriverName + "'"
            };
            using (var o = new ManagementObject(path))
            {
                var outParams = o.InvokeMethod(operation, null, null);
                return Convert.ToInt32(outParams.Properties["ReturnValue"].Value);
            }
        }

        private void OpenDevice()
        {
            LoadDeviceDriver();
            m_fileHandle = CreateFile("\\\\.\\" + DriverName, FileAccess.ReadWrite, FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
            if (m_fileHandle == INVALID_HANDLE_VALUE)
                Marshal.ThrowExceptionForHR(HRESULT_FROM_WIN32(Marshal.GetLastWin32Error()));
        }

        private static int HRESULT_FROM_WIN32(int x)
        {
            return x <= 0 ? x : ((x & 0x0000FFFF) | FACILITY_WIN32);
        }

        public void Dispose()
        {
            UnloadDeviceDriver();
            GC.SuppressFinalize(this);
        }

        protected void DeviceIoControl<T>(long functionId, T input)
        {
            DeviceIoControlHelper.InvokeIoControl(new SafeFileHandle(m_fileHandle, false), (IOControlCode)ControlCode(functionId), input);
        }
    }
}
