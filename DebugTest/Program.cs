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
            opts.executable = @"C:\Windows\System32\notepad.exe";
            opts.resumeOnCreate = false;

            NIDebugger64 debug = new NIDebugger64();
            debug.AutoClearBP = true;

            debug.Execute(opts);
            ulong memoryCave;
            debug.AllocateMemory(100, out memoryCave);

            debug.WriteString(memoryCave, "Welcome to NIDebugger64", Encoding.Unicode);

            ulong setWindowTextW = debug.FindProcAddress("user32.dll", "SetWindowTextW");
            debug.SetBreakpoint(setWindowTextW);

            debug.Continue();

            debug.Context.Rdx = memoryCave;

            debug.Detach();

            int i = 0;

        }
    }
}
