using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NonIntrusive64;
namespace DebugTest
{
    class Program
    {
        static void Main(string[] args)
        {
            NIStartupOptions opts = new NIStartupOptions();
            //opts.executable = @"C:\Users\Timothy\Documents\Visual Studio 2013\Projects\HelloCPP\x64\Release\HelloCPP.exe";
            //opts.executable = @"C:\Program Files\DuxCore\Visual DuxDebugger\VisualDuxDbg.exe";
            opts.executable = @"C:\Windows\System32\notepad.exe";
            opts.resumeOnCreate = false;

            NIDebugger64 debug = new NIDebugger64();
            debug.Execute(opts);

            byte[] data = new byte[4];
            ulong foo = debug.Context.Rcx;
            debug.ReadData(debug.Context.Rcx,4, out data);

            byte[] newData = new byte[4] { 0, 0, 0, 0 };
            debug.WriteData(debug.Context.Rcx, newData);

            byte[] data2 = new byte[4];
            debug.ReadData(debug.Context.Rcx, 4, out data2);

            debug.WriteData(debug.Context.Rcx, data);

            int i = 0;

        }
    }
}
