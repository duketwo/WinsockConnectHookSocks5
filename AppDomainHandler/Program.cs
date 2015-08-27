/*
 * ---------------------------------------
 * User: duketwo
 * Date: 11.12.2013
 * Time: 12:51
 * 
 * ---------------------------------------
 */

using System;
using System.Collections.Generic;
using System.Linq;
using EasyHook;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;

namespace IPCInterface
{

    public class Interface : MarshalByRefObject
    {
        public void Ping()
        {
        }
    }
}

namespace QuestorManager
{ 
    public class Main : IEntryPoint
    {
        [DllImport("kernel32.dll")]
        static extern void FreeLibraryAndExitThread(IntPtr hModule, uint dwExitCode);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
		IPCInterface.Interface iface;
        
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        /// 

        public Main(EasyHook.RemoteHooking.IContext InContext, string ChannelName, string[] args)
        {
            iface = RemoteHooking.IpcConnectClient<IPCInterface.Interface>(ChannelName);
            iface.Ping();
        }


        public void Run(EasyHook.RemoteHooking.IContext InContext, string ChannelName, string[] args)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;
            AppDomain hookManagerDomain = AppDomain.CreateDomain("WSockConnectHook");
            string assemblyFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            hookManagerDomain.ExecuteAssembly(assemblyFolder + "\\WSockConnectHook.exe");

            try
            {

                while (true)
                {
                    Thread.Sleep(100);
                    iface.Ping();
                }

            }
            catch
            {
                AppDomain.Unload(hookManagerDomain);
                AppDomain.Unload(currentDomain);
            }
        }
    }
}
