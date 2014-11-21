using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Katrina
{
    [Flags]
    public enum ContextFlags : uint
    {
        i386              = 0x10000,
        Control           = i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
        Integer           = i386 | 0x02, // AX, BX, CX, DX, SI, DI
        Segments          = i386 | 0x04, // DS, ES, FS, GS
        FloatingPoint     = i386 | 0x08, // 387 state
        DebugRegisters    = i386 | 0x10, // DB 0-3,6,7
        ExtendedRegisters = i386 | 0x20, // cpu specific extensions

        Full = Control | Integer | Segments,
        All  = Control | Integer | Segments | FloatingPoint | DebugRegisters | ExtendedRegisters
    }
    
    [StructLayout(LayoutKind.Sequential, Size = 0x60)]
    public struct DEBUG_EVENT
    {
        public uint Code;
        public int  ProcessId;
        public int  ThreadId;
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public uint ExceptionRecord;
        public uint ExceptionAddress;
        public uint NumberParameters;

        public bool IsProcessStoped
        {
            get { return Code == 9 || Code == 5; } // Rip or ExitProcess
        }

        public bool IsSingleStep
        {
            get { return Code == 1 && ExceptionCode == 0x80000004; } // Exception and STATUS_SINGLE_STEP
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public ContextFlags ContextFlags; //set this to an appropriate value 
        // Retrieved by CONTEXT_DEBUG_REGISTERS
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint[] Dr;
        public uint Dr6;
        public uint Dr7;
        // Retrieved by CONTEXT_FLOATING_POINT 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 112)]
        public byte[] FloatSave;
        // Retrieved by CONTEXT_SEGMENTS 
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        // Retrieved by CONTEXT_INTEGER 
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        // Retrieved by CONTEXT_CONTROL 
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        // Retrieved by CONTEXT_EXTENDED_REGISTERS 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    public class WinApi
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool DebugActiveProcess(int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool WaitForDebugEvent([In] ref DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        protected static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr OpenThread(uint DesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr thandle);

        [DllImport("kernel32", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr thandle);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr thandle, ref CONTEXT context);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr thandle, ref CONTEXT context);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern uint GetPrivateProfileString(string lpAppName, string lpKeyName, string lpDefault, StringBuilder lpReturnedString, int nSize, string lpFileName);
    
        public delegate bool ConsoleEventDelegate(int eventType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);
    }
}