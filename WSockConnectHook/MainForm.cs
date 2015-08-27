using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyHook;
using System.IO;

namespace WSockConnectHook
{
	public partial class MainForm : Form
	{
		public MainForm()
		{
			InitializeComponent();
			HookManager.Instance.InitHooks();
			RemoteHooking.WakeUpProcess();
			HookManager.OnMessage += ThreadSafeAddlog;
		}

		public void ThreadSafeAddlog(string str, Color? col)
		{
			if (this.InvokeRequired)
			{
				this.Invoke(new Action(() => AddLog(str, col)));

			}
			else
			{
				AddLog(str);
			}
		}

		void AddLog(string msg, Color? col = null)
		{

			col = col == null ? Color.Black : col;
			msg = DateTime.UtcNow.ToString() + " " + msg;
			var item = new ListViewItem();
			item.Text = msg;
			item.ForeColor = (Color)col;

			if (logbox.Items.Count >= 10000)
			{
				logbox.Items.Clear();
			}
			logbox.Items.Add(item);

			if (logbox.Items.Count > 1)
				logbox.Items[logbox.Items.Count - 1].EnsureVisible();

			
		}
		
	}
}
