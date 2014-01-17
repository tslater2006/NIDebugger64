﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NonIntrusive64
{
    public class Win64
    {
        #region DLL Imports
        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")]
        public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32.dll")]
        public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(ulong hProcess, ulong lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        [DllImport("kernel32.dll")]
        public static extern int CreateProcess(string lpApplicationName, string lpCommandLine, [MarshalAs(UnmanagedType.Struct)] ref  SECURITY_ATTRIBUTES lpProcessAttributes, [MarshalAs(UnmanagedType.Struct)] ref  SECURITY_ATTRIBUTES lpThreadAttributes, int bInheritHandles, int dwCreationFlags, int lpEnvironment, string lpCurrentDriectory, [MarshalAs(UnmanagedType.Struct)] ref  STARTUPINFO lpStartupInfo, [MarshalAs(UnmanagedType.Struct)] ref  PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")]
        public static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern int SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
        [DllImport("kernel32.dll")]
        public static extern int SetThreadContext(IntPtr hThread, [MarshalAs(UnmanagedType.Struct)] ref  CONTEXT lpContext);
        [DllImport("kernel32.dll")]
        public static extern int ReadProcessMemory(ulong hProcess, ulong lpBaseAddress, byte[] lpBuffer, int nSize, ref ulong lpNumberOfbytesWritten);
        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(ulong hProcess, ulong lpBaseAddress, byte[] lpBuffer, int nSize, ref ulong lpNumberOfbytesWritten);
        [DllImport("kernel32.dll")]
        public static extern void Sleep(int dwMilliseconds);
        [DllImport("kernel32.dll")]
        public static extern int GetTickCount();
        [DllImport("kernel32.dll")]
        public static extern int GetProcAddress(int hModule, string lpProcName);
        [DllImport("kernel32.dll")]
        public static extern int GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll")]
        public static extern int TerminateProcess(int hProcess, int uExitCode);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        #endregion
        #region Structs/Enums
        public struct MODULEENTRY32
        {
            const int MAX_PATH = 260;
            public UInt32 dwSize;
            public UInt32 th32ModuleID;
            public UInt32 th32ProcessID;
            public IntPtr GlblcntUsage;
            public UInt32 ProccntUsage;
            public IntPtr modBaseAddr;
            public UInt32 modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string szExePath;
            public UInt32 dwFlags;
        }
        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }
        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        /* Converted to x64 */
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public uint alignment1;
            public ulong RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
            public uint alignment2;
        }
        /* Converted to x64 */
        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_AMD64  = 0x00100000,
            CONTEXT_CONTROL = CONTEXT_AMD64 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_AMD64 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10, // DB 0-3,6,7
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS,
            CONTEXT_XSTATE = (CONTEXT_AMD64 | 0x40)
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public int wShowWindow;
            public int cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct XSAVE_FORMAT
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;

        }
        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public ulong Low;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct XMM_SAVE_AREA32
        {
            public XSAVE_FORMAT Save;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            //
            // Control flags.
            //

            public uint ContextFlags;
            public uint MxCsr;

            //
            // Segment Registers and processor flags.
            //

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            //
            // Debug registers
            //

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            //
            // Integer registers.
            //

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            public ulong Rip;

            public XMM_SAVE_AREA32 FltSave;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            //
            // Special debug control registers.
            //

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;

        }
        #endregion

        public const int CREATE_SUSPENDED = 0x4;
        public const int GET_CONTEXT = 0x8;
        public const int SET_CONTEXT = 0x0010;


    }
}
