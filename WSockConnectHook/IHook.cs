using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WSockConnectHook
{
    /// <summary>
    /// Description of IHook.
    /// </summary>
    public interface IHook : IDisposable
    {
        bool Error { get; set; }
        string Name { get; set; }
    }
}
