using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using RGiesecke.DllExport;

namespace _0xFFGame.ManagedHost
{
    public static class Program
    {
        [DllExport("LoadDomain", CallingConvention.StdCall)]
        public static void LoadDomain()
        {
            MessageBox.Show("FF Managed", "FFGame");
        }
    }
}
