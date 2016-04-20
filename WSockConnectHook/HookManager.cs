using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using System.Threading;
using System.Runtime.CompilerServices;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Diagnostics;
using EasyHook;

namespace WSockConnectHook
{
    public class HookManager
    {
        List<IHook> controllerList;
        

        public delegate void Message(string msg, Color? col);
        public static event Message OnMessage;
        protected static readonly object _lock = new object();

        [DllImport("kernel32.dll")]
        static extern bool SetProcessWorkingSetSize(IntPtr hProcess, uint
                                                    dwMinimumWorkingSetSize, uint dwMaximumWorkingSetSize);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("user32.dll")]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr FindWindowEx(IntPtr parentHandle, IntPtr childAfter, string lclassName, string windowTitle);

        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        public HookManager()
        {
        	
        	controllerList = new List<IHook>();
        }

        public void AddController(IHook controller)
        {
            if (!controllerList.Contains(controller))
                controllerList.Add(controller);
        }
        public void RemoveController(IHook controller)
        {
            controllerList.Remove(controller);
        }
        public void DisposeHooks()
        {
            foreach (var controller in controllerList)
            {
                    controller.Dispose();
     
            }
        }

        public void InitHooks()
        {
            Utility.LoadLibrary("WS2_32.dll");
            Log(LocalHook.GetProcAddress("WS2_32.dll", "connect").ToString());
            AddController(new WinSockConnectController(LocalHook.GetProcAddress("WS2_32.dll", "connect"), "127.0.0.1", "1337", "username", "password"));
          
        }


        public static void Log(string text, Color? col = null)
        {
            lock (_lock)
            {
                Thread thread = new Thread(delegate () { _Log(text, col); });
                thread.Start();
            }
        }

        private static void _Log(string text, Color? col)
        {
            try
            {
                if (OnMessage != null)
                {
                    OnMessage(text, col);
                }
            }
            catch (Exception)
            {
            }

        }

        private static readonly HookManager _instance = new HookManager();
        public static HookManager Instance
        {
            get { return _instance; }
        }
    }
}
