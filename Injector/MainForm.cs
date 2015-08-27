using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using EasyHook;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.Remoting;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO;

using System.Threading;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.Serialization;


namespace IPCInterface
{

    public class Interface : MarshalByRefObject
    {
        public void Ping()
        {
        }
    }
}

namespace Injector
{

 

    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {

            string[] args = new string[] {};
            string path = System.IO.Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string injectionFile = System.IO.Path.Combine(path, "AppDomainHandler.dll");
            String ChannelName = null;
            RemoteHooking.IpcCreateServer<IPCInterface.Interface>(ref ChannelName, WellKnownObjectMode.SingleCall);
            int processId = -1;
           //EasyHook.RemoteHooking.CreateAndInject("D:\\eveoffline\\bin\\exefile.exe", "", (int)InjectionOptions.Default, injectionFile, injectionFile, out processId, ChannelName, args);
           EasyHook.RemoteHooking.CreateAndInject("C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe", "http://www.google.de", (int)InjectionOptions.Default, injectionFile, injectionFile, out processId, ChannelName, args);
           
           
        }
    }
}
