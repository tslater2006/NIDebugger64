using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LDASM_Sharp;

namespace NonIntrusive64
{
    public class NIDebugger64
    {
        Win64.PROCESS_INFORMATION debuggedProcessInfo;
        Process debuggedProcess;
        NIBreakPoint lastBreakpoint;
        Dictionary<ulong, NIBreakPoint> breakpoints = new Dictionary<ulong, NIBreakPoint>();
        Dictionary<int, IntPtr> threadHandles = new Dictionary<int, IntPtr>();
        private byte[] BREAKPOINT = new byte[] { 0xEB, 0xFE };
        private static ManualResetEvent mre = new ManualResetEvent(false);
        LDASM lde = new LDASM();

        BackgroundWorker bwContinue;

        /// <summary>
        /// Determines if a BreakPoint should be cleared automatically once it is hit. The default is True
        /// </summary>
        public bool AutoClearBP { get; set; }
        public bool StepIntoCalls { get; set; }
        public Win64.CONTEXT Context;

        /// <summary>
        /// Helper method that simplifies setting a BreakPoint on a function in the debugged process. Usefull only for functions that are exported from their associated modules.
        /// </summary>
        /// <param name="module">The module that holds the method.</param>
        /// <param name="method">The method to set a BreakPoint on.</param>
        /// <returns></returns>
        public NIDebugger64 SetProcBP(String module, String method)
        {
            SetBreakpoint(FindProcAddress(module, method));
            return this;
        }

        /// <summary>
        /// Helper method that simplifies clearing a BreakPoint on a function in the debugged process. Usefull only for functions that are exported from their associated modules.
        /// </summary>
        /// <param name="module">The module that holds the method.</param>
        /// <param name="method">The method to clear a BreakPoint from.</param>
        /// <returns></returns>
        public NIDebugger64 ClearProcBP(String module, String method)
        {
            ClearBreakpoint(FindProcAddress(module, method));
            return this;
        }

        public NIDebugger64 Execute(NIStartupOptions opts)
        {
            Win64.SECURITY_ATTRIBUTES sa1 = new Win64.SECURITY_ATTRIBUTES();
            sa1.nLength = Marshal.SizeOf(sa1);
            Win64.SECURITY_ATTRIBUTES sa2 = new Win64.SECURITY_ATTRIBUTES();
            sa2.nLength = Marshal.SizeOf(sa2);
            Win64.STARTUPINFO si = new Win64.STARTUPINFO();
            debuggedProcessInfo = new Win64.PROCESS_INFORMATION();
            int ret = Win64.CreateProcess(opts.executable, opts.commandLine, ref sa1, ref sa2, 0, 0x00000200 | Win64.CREATE_SUSPENDED, 0, null, ref si, ref debuggedProcessInfo);

            debuggedProcess = Process.GetProcessById(debuggedProcessInfo.dwProcessId);
            threadHandles.Add(debuggedProcessInfo.dwThreadId, debuggedProcessInfo.hThread);

            if (opts.resumeOnCreate)
            {
                Win64.ResumeThread((IntPtr)debuggedProcessInfo.hThread);
            }
            else
            {
                Context = getContext(getCurrentThreadId());

                ulong OEP = Context.Rcx;

                SetBreakpoint(OEP);
                Continue();
                ClearBreakpoint(OEP);

                Console.WriteLine("We should be at OEP");

            }



            return this;

        }

        /// <summary>
        /// Sets a BreakPoint at a given address in the debugged process.
        /// </summary>
        /// <param name="address">The address at which a BreakPoint should be placed.</param>
        /// <returns></returns>
        public NIDebugger64 SetBreakpoint(ulong address)
        {
            if (breakpoints.Keys.Contains(address) == false)
            {
                NIBreakPoint bp = new NIBreakPoint() { bpAddress = address };
                byte[] origBytes;
                ReadData(address, 2, out origBytes);
                bp.originalBytes = origBytes;

                breakpoints.Add(address, bp);
                WriteData(address, BREAKPOINT);
            }
            return this;
        }
        /// <summary>
        /// Clears a BreakPoint that has been previously set in the debugged process.
        /// </summary>
        /// <param name="address">The address at which the BreakPoint should be removed.</param>
        /// <returns></returns>
        public NIDebugger64 ClearBreakpoint(ulong address)
        {
            if (breakpoints.Keys.Contains(address))
            {

                WriteData(address, breakpoints[address].originalBytes);
                breakpoints.Remove(address);
            }
            return this;
        }

        /// <summary>
        /// Reads binary data from the debugged process, starting at a given address and reading a given amount of bytes.
        /// </summary>
        /// <param name="address">The address to begin reading.</param>
        /// <param name="length">The number of bytes to read.</param>
        /// <param name="output">The output variable that will contain the read data.</param>
        /// <returns></returns>
        public NIDebugger64 ReadData(ulong address, int length, out byte[] output)
        {
            ulong numRead = 0;
            byte[] data = new byte[length];
            Win64.ReadProcessMemory((ulong)debuggedProcessInfo.hProcess, address, data, length, ref numRead);

            output = data;

            return this;
        }

        public NIDebugger64 WriteData(ulong address, byte[] data)
        {
            Win64.MEMORY_BASIC_INFORMATION mbi = new Win64.MEMORY_BASIC_INFORMATION();

            Win64.VirtualQueryEx((ulong)debuggedProcessInfo.hProcess, address, out mbi, (uint)Marshal.SizeOf(mbi));
            uint oldProtect = 0;

            Win64.VirtualProtectEx((IntPtr)debuggedProcessInfo.hProcess, (IntPtr)mbi.BaseAddress, (UIntPtr)mbi.RegionSize, (uint)Win64.AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out oldProtect);

            ulong numWritten = 0;
            Win64.WriteProcessMemory((ulong)debuggedProcessInfo.hProcess, address, data, data.Length, ref numWritten);

            Win64.VirtualProtectEx((IntPtr)debuggedProcessInfo.hProcess, (IntPtr)mbi.BaseAddress, (UIntPtr)mbi.RegionSize, oldProtect, out oldProtect);

            return this;
        }

        /// <summary>
        /// Writes a String to a given address in the debugged process, using the specificied string encoding.
        /// </summary>
        /// <param name="address">The address to write the String.</param>
        /// <param name="str">The String to be written.</param>
        /// <param name="encode">The encoding that should be used for the String.</param>
        /// <returns></returns>
        public NIDebugger64 WriteString(ulong address, String str, Encoding encode)
        {
            return WriteData(address, encode.GetBytes(str));
        }
        /// <summary>
        /// Terminates the debugged process.
        /// </summary>
        public void Terminate()
        {
            Detach();
            debuggedProcess.Kill();
        }

        /// <summary>
        /// Detaches the debugger from the debugged process.
        /// This is done by removing all registered BreakPoints and then resuming the debugged process.
        /// </summary>
        /// <returns></returns>
        public NIDebugger64 Detach()
        {
            pauseAllThreads();
            foreach (uint addr in breakpoints.Keys)
            {
                ClearBreakpoint(addr);
            }
            updateContext(getCurrentThreadId());
            resumeAllThreads();
            return this;
        }
        /// <summary>
        /// Allocates memory in the debugged process.
        /// </summary>
        /// <param name="size">The number of bytes to allocate.</param>
        /// <param name="address">The output variable containing the address of the allocated memory.</param>
        /// <returns></returns>
        public NIDebugger64 AllocateMemory(uint size, out ulong address)
        {
            IntPtr memLocation = Win64.VirtualAllocEx((IntPtr)debuggedProcessInfo.hProcess, new IntPtr(), size, (uint)Win64.StateEnum.MEM_RESERVE | (uint)Win64.StateEnum.MEM_COMMIT, (uint)Win64.AllocationProtectEnum.PAGE_EXECUTE_READWRITE);

            address = (ulong)memLocation;
            return this;
        }

        /// <summary>
        /// Reads a String from a given address in the debugged process, using the specificied string encoding.
        /// </summary>
        /// <param name="address">The address to begin reading the String.</param>
        /// <param name="maxLength">The maximum length of the String to be read.</param>
        /// <param name="encode">The encoding that the String uses.</param>
        /// <param name="value">The output variable that will hold the read value.</param>
        /// <returns></returns>
        public NIDebugger64 ReadString(ulong address, int maxLength, Encoding encode, out String value)
        {
            byte[] data;
            ReadData(address, maxLength, out data);
            value = "";
            if (encode.IsSingleByte)
            {
                for (int x = 0; x < data.Length - 1; x++)
                {
                    if (data[x] == 0)
                    {
                        value = encode.GetString(data, 0, x + 1);
                        break;
                    }
                }
            }
            else
            {
                for (int x = 0; x < data.Length - 2; x++)
                {
                    if (data[x] + data[x + 1] == 0)
                    {
                        value = encode.GetString(data, 0, x + 1);
                        break;
                    }
                }
            }
            return this;
        }

        /// <summary>
        /// Reads a DWORD value from the debugged process at a given address.
        /// </summary>
        /// <param name="address">The address to begin reading the DWORD value</param>
        /// <param name="value">The output variable that will hold the read value.</param>
        /// <returns></returns>
        public NIDebugger64 ReadQWORD(ulong address, out ulong value)
        {
            byte[] data;
            ReadData(address, 8, out data);
            value = BitConverter.ToUInt64(data, 0);
            return this;
        }

        /// <summary>
        /// Writes a DWORD value to the memory of a debugged process.
        /// </summary>
        /// <param name="address">The address to begin writing the DWORD value.</param>
        /// <param name="value">The value to be written.</param>
        /// <returns></returns>
        public NIDebugger64 WriteQWORD(ulong address, ulong value)
        {
            byte[] data = BitConverter.GetBytes(value);
            return WriteData(address, data);
        }


        /// <summary>
        /// Reads a DWORD value from the debugged process at a given address.
        /// </summary>
        /// <param name="address">The address to begin reading the DWORD value</param>
        /// <param name="value">The output variable that will hold the read value.</param>
        /// <returns></returns>
        public NIDebugger64 ReadDWORD(ulong address, out uint value)
        {
            byte[] data;
            ReadData(address, 4, out data);
            value = BitConverter.ToUInt32(data, 0);
            return this;
        }
        private Win64.MODULEENTRY32 getModule(String modName)
        {
            IntPtr hSnap = Win64.CreateToolhelp32Snapshot(Win64.SnapshotFlags.NoHeaps | Win64.SnapshotFlags.Module, (uint)debuggedProcessInfo.dwProcessId);
            Win64.MODULEENTRY32 module = new Win64.MODULEENTRY32();
            module.dwSize = (uint)Marshal.SizeOf(module);
            Win64.Module32First(hSnap, ref module);

            if (module.szModule.Equals(modName, StringComparison.CurrentCultureIgnoreCase))
            {
                return module;
            }

            while (Win64.Module32Next(hSnap, ref module))
            {
                if (module.szModule.Equals(modName, StringComparison.CurrentCultureIgnoreCase))
                {
                    return module;
                }
            }
            module = new Win64.MODULEENTRY32();
            Win64.CloseHandle(hSnap);
            return module;
        }

        /// <summary>
        /// Gets the length of the current instruction. This is based on the current value of EIP.
        /// </summary>
        /// <returns>The length (in bytes) of the current instruction.</returns>
        public uint GetInstrLength()
        {

            ulong address = Context.Rip;

            byte[] data;
            ReadData(address, 16, out data);
            if (breakpoints.ContainsKey(address) == true)
            {
                Array.Copy(breakpoints[address].originalBytes, data, 2);
            }

            return lde.ldasm(data, 0, true).size;
        }

        /// <summary>
        /// Gets the opcodes for the current instruction.
        /// </summary>
        /// <returns>Byte array consisting of the opcodes for the current instruction.</returns>
        public byte[] GetInstrOpcodes()
        {
            ulong address = Context.Rip;
            byte[] data;
            ReadData(address, 16, out data);

            if (breakpoints.ContainsKey(address) == true)
            {
                Array.Copy(breakpoints[address].originalBytes, data, 2);
            }

            uint size = lde.ldasm(data, 0, false).size;

            byte[] codes = new byte[size];
            Array.Copy(data, codes, size);

            return codes;
        }

        /// <summary>
        /// Finds the address for the given method inside the given module. 
        /// The method requested must be exported to be found. 
        /// This is equivalent to the GetProcAddress() Win64 API but takes into account ASLR by reading the export tables directly from the loaded modules within the debugged process.
        /// </summary>
        /// <param name="modName">Name of the DLL that contains the function (must include extension)</param>
        /// <param name="method">The method whose address is being requested.</param>
        /// <returns>The address of the method if it was found</returns>
        /// <exception cref="System.Exception">Target doesn't have module:  + modName +  loaded.</exception>
        public ulong FindProcAddress(String modName, String method)
        {
            Win64.MODULEENTRY32 module = getModule(modName);

            if (module.dwSize == 0)
            {
                Console.WriteLine("Failed to find module");
                throw new Exception("Target doesn't have module: " + modName + " loaded.");
            }
            ulong modBase = (ulong)module.modBaseAddr;

            uint peAddress, exportTableAddress, exportTableSize;
            byte[] exportTable;

            ReadDWORD(modBase + 0x3c, out peAddress);

            ReadDWORD(modBase + peAddress + 0x88, out exportTableAddress);
            ReadDWORD(modBase + peAddress + 0x8C, out exportTableSize);

            ReadData(modBase + exportTableAddress, (int)exportTableSize, out exportTable);

            ulong exportEnd = modBase + exportTableAddress + exportTableSize;


            uint numberOfFunctions = BitConverter.ToUInt32(exportTable, 0x14);
            uint numberOfNames = BitConverter.ToUInt32(exportTable, 0x18);

            uint functionAddressBase = BitConverter.ToUInt32(exportTable, 0x1c);
            uint nameAddressBase = BitConverter.ToUInt32(exportTable, 0x20);
            uint ordinalAddressBase = BitConverter.ToUInt32(exportTable, 0x24);

            StringBuilder sb = new StringBuilder();
            for (int x = 0; x < numberOfNames; x++)
            {
                sb.Clear();
                uint namePtr = BitConverter.ToUInt32(exportTable, (int)(nameAddressBase - exportTableAddress) + (x * 4)) - exportTableAddress;

                while (exportTable[namePtr] != 0)
                {
                    sb.Append((char)exportTable[namePtr]);
                    namePtr++;
                }

                ushort funcOrdinal = BitConverter.ToUInt16(exportTable, (int)(ordinalAddressBase - exportTableAddress) + (x * 2));


                ulong funcAddress = BitConverter.ToUInt32(exportTable, (int)(functionAddressBase - exportTableAddress) + (funcOrdinal * 4));
                funcAddress += modBase;

                if (sb.ToString().Equals(method))
                {
                    return funcAddress;
                }

            }
            return 0;


        }


        /// <summary>
        /// Signals that the debugged process should be resumed, and that the debugger should continue to monitor for BreakPoint hits.
        /// </summary>
        /// <returns></returns>
        public NIDebugger64 Continue()
        {
            getContext(getCurrentThreadId());

            bwContinue = new BackgroundWorker();
            bwContinue.DoWork += bw_Continue;

            mre.Reset();
            bwContinue.RunWorkerAsync();
            mre.WaitOne();

            if (AutoClearBP)
            {
                ClearBreakpoint(lastBreakpoint.bpAddress);
            }
            return this;
        }

        private void pauseAllThreads()
        {
            foreach (ProcessThread t in debuggedProcess.Threads)
            {
                IntPtr hThread = getThreadHandle(t.Id);
                Win64.SuspendThread(hThread);
            }
        }

        private void resumeAllThreads()
        {
            foreach (ProcessThread t in debuggedProcess.Threads)
            {
                IntPtr hThread = getThreadHandle(t.Id);
                int result = Win64.ResumeThread(hThread);
                while (result > 1)
                {
                    result = Win64.ResumeThread(hThread);
                }
            }
        }

        private void bw_Continue(object sender, DoWorkEventArgs e)
        {
            BackgroundWorker worker = sender as BackgroundWorker;
            while (1 == 1)
            {
                if (debuggedProcess.HasExited)
                {
                    return;
                }
                pauseAllThreads();
                //Console.WriteLine("threads paused");
                foreach (ulong address in breakpoints.Keys)
                {
                    foreach (ProcessThread pThread in debuggedProcess.Threads)
                    {
                        if (getContext(pThread.Id).Rip == address)
                        {
                            Console.WriteLine("We hit a breakpoint: " + address.ToString("X"));
                            lastBreakpoint = breakpoints[address];
                            lastBreakpoint.threadId = (uint)pThread.Id;

                            getContext(pThread.Id);

                            e.Cancel = true;
                            mre.Set();
                            return;
                        }
                    }
                }
                resumeAllThreads();
                //Console.WriteLine("threads resumed");
            }
        }

        /// <summary>
        /// Writes a DWORD value to the memory of a debugged process.
        /// </summary>
        /// <param name="address">The address to begin writing the DWORD value.</param>
        /// <param name="value">The value to be written.</param>
        /// <returns></returns>
        public NIDebugger64 WriteDWORD(ulong address, uint value)
        {
            byte[] data = BitConverter.GetBytes(value);
            return WriteData(address, data);
        }

        public NIDebugger64 ReadStackValue(uint rspOffset, out ulong value)
        {
            ReadQWORD(Context.Rsp + rspOffset, out value);
            return this;
        }

        /// <summary>
        /// Helper method that simplifies writing a value to the stack.
        /// </summary>
        /// <param name="espOffset">The offset based on ESP to write.</param>
        /// <param name="value">The value to be written.</param>
        /// <returns></returns>
        public NIDebugger64 WriteStackValue(uint rspOffset, uint value)
        {
            return WriteDWORD(Context.Rsp + rspOffset, value);
        }

        #region Delegate Methods
        /// <summary>
        /// This method continues to run the specifed action while the specified condition results in True
        /// </summary>
        /// <param name="condition">Method to be used in determining if Action should be performed, this method MUST return a boolean value.</param>
        /// <param name="action">The action delegate to be performed while Condition resolves to True</param>
        /// <returns></returns>
        public NIDebugger64 While(Func<bool> condition, Action action)
        {
            while (condition())
            {
                action();
            }

            return this;
        }

        /// <summary>
        /// This method continues to run the specifed action until the specified condition results in True
        /// </summary>
        /// <param name="condition">Method to be used in determining if Action should be performed, this method MUST return a boolean value.</param>
        /// <param name="action">The action delegate to be performed until Condition resolves to True.</param>
        /// <returns></returns>
        public NIDebugger64 Until(Func<bool> condition, Action action)
        {
            while (condition() != true)
            {
                action();
            }

            return this;
        }

        /// <summary>
        /// Runs a given Action count number of times.
        /// </summary>
        /// <param name="count">The number of times an Action should be run.</param>
        /// <param name="action">The action to be run.</param>
        /// <returns></returns>
        public NIDebugger64 Times(uint count, Action action)
        {
            for (uint x = 0; x < count; x++)
            {
                action();
            }
            return this;
        }

        /// <summary>
        /// This method runs the given Action if the specified condition results in True
        /// </summary>
        /// <param name="condition">Method to be used in determining if Action should be performed, this method MUST return a boolean value.</param>
        /// <param name="action">The action delegate to be performed if the condition evaluates to True.</param>
        /// <returns></returns>
        public NIDebugger64 If(Func<bool> condition, Action action)
        {
            if (condition())
            {
                action();
            }

            return this;
        }
        #endregion

        private int getCurrentThreadId()
        {
            if (lastBreakpoint == null)
            {
                return debuggedProcessInfo.dwThreadId;
            } else
            {
                return (int)lastBreakpoint.threadId;
            }
        }

        private void updateContext(int threadId)
        {
            IntPtr hThread = getThreadHandle(threadId);
            Win64.CONTEXT ctx = Context;
            Win64.SetThreadContext(hThread, ref ctx);
        }

        private Win64.CONTEXT getContext(int threadId)
        {

            IntPtr hThread = getThreadHandle(threadId);

            Win64.CONTEXT ctx = new Win64.CONTEXT();
            ctx.ContextFlags = (uint)Win64.CONTEXT_FLAGS.CONTEXT_ALL;
            Win64.GetThreadContext(hThread, ref ctx);
            int foo = Marshal.SizeOf(ctx);
            Context = ctx;
            return ctx;
        }

        private IntPtr getThreadHandle(int threadId)
        {
            return threadHandles[threadId];
        }

        /// <summary>
        /// Performs a SingleStep operation, that is to stay it resumes the process and pauses at the very next instruction.
        /// Jumps are followed, conditional jumps are evaluated, Calls are either stepped into or over depending on StepIntoCalls value.
        /// </summary>
        /// <returns></returns>
        public NIDebugger64 SingleStep()
        {
            getContext(getCurrentThreadId());
            ulong address = Context.Rip;
            if (address == 0x7ffa79b6660e)
            {
                int i = 0;
            }
            byte[] data;
            ReadData(address, 16, out data);

            if (breakpoints.ContainsKey(address) == true)
            {
                Array.Copy(breakpoints[address].originalBytes, data, 2);
                ClearBreakpoint(address);
            }

            ldasm_data ldata = lde.ldasm(data, 0, false);

            uint size = ldata.size;
            ulong nextAddress = Context.Rip + size;

            if (ldata.opcd_size == 1 && (data[ldata.opcd_offset] == 0xEB))
            {
                // we have a 1 byte JMP here
                sbyte offset = (sbyte)data[ldata.imm_offset];
                nextAddress = (ulong)((long)Context.Rip + offset) + ldata.size;
            }

            if ((data[ldata.opcd_offset] == 0xE2))
            {
                // LOOP

                if (Context.Rcx == 1)
                {
                    // this instruction will make ECX 0, so we fall thru the jump now
                    nextAddress = (ulong)((long)Context.Rip + ldata.size);

                }
                else if (Context.Rcx > 1)
                {
                    // this instruction will decrement ECX but it wont be 0 yet, so jump!
                    sbyte disp = (sbyte)data[1];
                    nextAddress = (uint)((long)Context.Rip + disp) + ldata.size;
                }


            }

            if ((data[ldata.opcd_offset] == 0xE0))
            {
                //LOOPNZ LOOPNE
                if (Context.Rcx == 1 && Context.GetFlag(NIContextFlag.ZERO) == false)
                {
                    nextAddress = (ulong)((long)Context.Rip + ldata.size);
                }
                else if (Context.Rcx > 1 || Context.GetFlag(NIContextFlag.ZERO) != false)
                {
                    sbyte disp = (sbyte)data[1];
                    nextAddress = (ulong)((long)Context.Rip + disp) + ldata.size;
                }
            }

            if ((data[ldata.opcd_offset] == 0xE1))
            {
                //LOOPZ LOOPE
                if (Context.Rcx == 1 && Context.GetFlag(NIContextFlag.ZERO) == true)
                {
                    nextAddress = (ulong)((long)Context.Rip + ldata.size);
                }
                else if (Context.Rcx > 1 || Context.GetFlag(NIContextFlag.ZERO) != true)
                {
                    sbyte disp = (sbyte)data[1];
                    nextAddress = (ulong)((long)Context.Rip + disp) + ldata.size;
                }
            }

            if (ldata.opcd_size == 1 && ((data[ldata.opcd_offset] == 0xE9) || (data[ldata.opcd_offset] == 0xE8)))
            {
                // we have a long JMP or CALL here
                int offset = BitConverter.ToInt32(data, ldata.imm_offset);
                if ((data[ldata.opcd_offset] == 0xE9) || (StepIntoCalls && (data[ldata.opcd_offset] == 0xE8)))
                {
                    nextAddress = (ulong)((long)Context.Rip + offset) + ldata.size;
                }

            }

            if (ldata.opcd_size == 1 && ((data[ldata.opcd_offset] >= 0x70 && (data[ldata.opcd_offset] <= 0x7F)) || (data[ldata.opcd_offset] == 0xE3)))
            {
                // we have a 1byte jcc here
                bool willJump = evalJcc(data[ldata.opcd_offset]);

                if (willJump)
                {
                    sbyte offset = (sbyte)data[ldata.imm_offset];
                    nextAddress = (ulong)((long)Context.Rip + offset) + ldata.size;
                }
            }

            if (ldata.opcd_size == 2 && ((data[ldata.opcd_offset] == 0x0F) || (data[ldata.opcd_offset + 1] == 0x80)))
            {
                // we have a 2 byte jcc here

                bool willJump = evalJcc(data[ldata.opcd_offset + 1]);

                if (willJump)
                {
                    int offset = BitConverter.ToInt32(data, ldata.imm_offset);
                    nextAddress = (ulong)(((long)Context.Rip + offset) + ldata.size);
                }
            }

            if (data[ldata.opcd_offset] == 0xC3 || data[ldata.opcd_offset] == 0xC2)
            {
                ReadStackValue(0, out nextAddress);
            }

            if (data[ldata.opcd_offset] == 0xFF && ldata.opcd_size == 1 && ldata.modrm != 0x00)
            {
                // let's parse ModRM!
                var reg2 = (ldata.modrm & 0x38) >> 3;
                var mod = (ldata.modrm & 0xC0) >> 6;
                var reg1 = (ldata.modrm & 0x7);
                bool addressSet = false;
                if (reg2 == 2)
                {
                    if (StepIntoCalls == false)
                    {
                        nextAddress = (uint)Context.Rip + ldata.size;
                        addressSet = true;
                    }

                    Console.Write("RegOp tells me this is a CALL\r\n");
                }
                else if (reg2 == 4)
                {
                    Console.Write("RegOp tells me this is a JMP\r\n");
                }
                else
                {
                    nextAddress = (uint)Context.Rip + ldata.size;
                    addressSet = true;
                }

                if (addressSet == false)
                {
                    if (reg1 == 4)
                    {
                        //txtFacts.Text += "Reg1 is a 4 which means there is a SIB byte\r\n";
                        var ss = (ldata.sib & 0xC0) >> 6;
                        var index = (ldata.sib & 0x38) >> 3;
                        var Base = (ldata.sib & 0x07);


                        int scale = (int)Math.Pow(2, ss);
                        nextAddress = (uint)GetRegisterByNumber(index) * (uint)scale;
                        if (Base == 5)
                        {
                            if (mod == 0)
                            {
                                nextAddress = (uint)((int)nextAddress + BitConverter.ToInt32(data, ldata.disp_offset));
                            }
                            else if (mod == 1)
                            {
                                nextAddress += GetRegisterByNumber(Base);
                                nextAddress = (uint)((int)(nextAddress) + (sbyte)data[ldata.disp_offset]);
                            }
                            else if (mod == 2)
                            {
                                nextAddress += GetRegisterByNumber(Base);
                                nextAddress = (uint)((int)nextAddress + BitConverter.ToInt32(data, ldata.disp_offset));
                            }
                        }

                    }
                    else
                    {
                        if (mod == 0)
                        {
                            if (reg1 != 5)
                            {
                                nextAddress = GetRegisterByNumber(reg1);
                            }
                            else
                            {
                                nextAddress = (uint)BitConverter.ToInt32(data, ldata.disp_offset);
                            }

                        }
                        else if (mod == 1)
                        {
                            nextAddress = GetRegisterByNumber(reg1);
                            nextAddress = (uint)((int)(nextAddress) + (sbyte)data[ldata.disp_offset]);

                        }
                        else if (mod == 2)
                        {
                            nextAddress = GetRegisterByNumber(reg1);
                            nextAddress = (uint)((int)nextAddress + BitConverter.ToInt32(data, ldata.disp_offset));
                        }
                    }
                    if (mod != 3)
                    {
                        //ReadDWORD(nextAddress, out nextAddress);
                    }

                    Console.WriteLine("Next Address: " + nextAddress.ToString("X8"));
                }
            }

            updateContext(getCurrentThreadId());
            SetBreakpoint(nextAddress);

            Continue();

            ClearBreakpoint(nextAddress);

            return this;

        }
        private bool evalJcc(byte b)
        {
            if ((b & 0x80) == 0x80) { b -= 0x80; }
            if ((b & 0x70) == 0x70) { b -= 0x70; }

            bool willJump = false;
            // determine if we will jump
            switch (b)
            {
                case 0:
                    willJump = Context.GetFlag(NIContextFlag.OVERFLOW);
                    break;
                case 1:
                    willJump = !Context.GetFlag(NIContextFlag.OVERFLOW);
                    break;
                case 2:
                    willJump = Context.GetFlag(NIContextFlag.CARRY);
                    break;
                case 3:
                    willJump = !Context.GetFlag(NIContextFlag.CARRY);
                    break;
                case 4:
                    willJump = Context.GetFlag(NIContextFlag.ZERO);
                    break;
                case 5:
                    willJump = !Context.GetFlag(NIContextFlag.ZERO);
                    break;
                case 6:
                    willJump = Context.GetFlag(NIContextFlag.CARRY) || Context.GetFlag(NIContextFlag.ZERO);
                    break;
                case 7:
                    willJump = (!Context.GetFlag(NIContextFlag.CARRY)) && (!Context.GetFlag(NIContextFlag.ZERO));
                    break;
                case 8:
                    willJump = Context.GetFlag(NIContextFlag.SIGN);
                    break;
                case 9:
                    willJump = !Context.GetFlag(NIContextFlag.SIGN);
                    break;
                case 0x0a:
                    willJump = Context.GetFlag(NIContextFlag.PARITY);
                    break;
                case 0x0b:
                    willJump = !Context.GetFlag(NIContextFlag.PARITY);
                    break;
                case 0x0c:
                    willJump = Context.GetFlag(NIContextFlag.SIGN) != Context.GetFlag(NIContextFlag.OVERFLOW);
                    break;
                case 0x0d:
                    willJump = Context.GetFlag(NIContextFlag.SIGN) == Context.GetFlag(NIContextFlag.OVERFLOW);
                    break;
                case 0x0e:
                    willJump = Context.GetFlag(NIContextFlag.ZERO) || (Context.GetFlag(NIContextFlag.SIGN) != Context.GetFlag(NIContextFlag.OVERFLOW));
                    break;
                case 0x0f:
                    willJump = !Context.GetFlag(NIContextFlag.ZERO) && (Context.GetFlag(NIContextFlag.SIGN) == Context.GetFlag(NIContextFlag.OVERFLOW));
                    break;
                case 0xE3:
                    willJump = Context.Rcx == 0;
                    break;
            }
            return willJump;
        }
        private ulong GetRegisterByNumber(int val)
        {
            switch (val)
            {
                case 0:
                    return Context.Rax;
                case 1:
                    return Context.Rcx;
                case 2:
                    return Context.Rdx;
                case 3:
                    return Context.Rbx;
                case 4:
                    return 0;
                case 5:
                    return Context.Rbp;
                case 6:
                    return Context.Rsi;
                case 7:
                    return Context.Rdi;
                default:
                    return 0;
            }
        }

    }

    public static class NIExtensions
    {
        public static bool GetFlag(this Win64.CONTEXT ctx, NIContextFlag i)
        {
            return (ctx.EFlags & (uint)i) == (uint)i;
        }

        public static void SetFlag(this Win64.CONTEXT ctx, NIContextFlag i, bool value)
        {
            ctx.EFlags -= ctx.GetFlag(i) ? (uint)i : 0;

            ctx.EFlags ^= (value) ? (uint)i : 0;
        }
    }

    /// <summary>
    /// Enumeration for the various Flags.
    /// </summary>
    public enum NIContextFlag : uint
    {
        CARRY = 0x01, PARITY = 0x04, ADJUST = 0x10, ZERO = 0x40, SIGN = 0x80, DIRECTION = 0x400, OVERFLOW = 0x800
    }
    public class NIStartupOptions
    {
        /// <summary>
        /// Gets or sets the path to the executable to be run.
        /// </summary>
        /// <value>
        /// The executable path.
        /// </value>
        public string executable { get; set; }
        /// <summary>
        /// Gets or sets the command line arguments.
        /// </summary>
        /// <value>
        /// The command line arguments.
        /// </value>
        public string commandLine { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether the debugged process should be resumed immediately after creation, or if it should remain paused until Continue() is called.
        /// </summary>
        /// <value>
        /// If this is set to true, the debugged process will be started immediately after creation, otherwise it is left in a suspended state.
        /// </value>
        public bool resumeOnCreate { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the Win64 API call GetTickCount should be patched.
        /// </summary>
        /// <value>
        /// If this is set to true, the call will be patched (how it is patched is determine by the value of incrementTickCount), otherwise the method will be left alone.
        /// </value>
        public bool patchTickCount { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether GetTickCount should always return 1, or if it should return increasing numbers.
        /// </summary>
        /// <value>
        /// If this is set to true, GetTickCount will return increasing numbers, otherwise it will always return 1.
        /// </value>
        public bool incrementTickCount { get; set; }
    }

    public class NIBreakPoint
    {
        /// <summary>
        /// Gets or sets the address of the BreakPoint.
        /// </summary>
        /// <value>
        /// The address of the BreakPoint.
        /// </value>
        public ulong bpAddress { get; set; }
        /// <summary>
        /// Gets or sets the original bytes that were overwritten by the BreakPoint.
        /// </summary>
        /// <value>
        /// The original bytes that were overwritten by the BreakPoint.
        /// </value>
        public byte[] originalBytes { get; set; }

        /// <summary>
        /// Gets or sets the thread identifier. This value is populated once a BreakPoint has been hit to show which thread has hit it.
        /// </summary>
        /// <value>
        /// The thread identifier associated with this BreakPoint. This value is only valid in the context of a BreakPoint that has been hit.
        /// </value>
        public uint threadId { get; set; }
    }
}
