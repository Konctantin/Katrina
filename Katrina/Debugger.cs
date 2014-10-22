using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;

namespace Katrina
{
    public delegate void DebugExceptionHandler(Process process, CONTEXT context);

    public class Debugger : WinApi
    {
        delegate void ThreadContextHandler(ref CONTEXT context);

        private Dictionary<uint, DebugExceptionHandler> breakpoints = new Dictionary<uint, DebugExceptionHandler>();
        private bool isDebugging = true;
        private Process process = null;
        private ProcessThread thread = null;

        public Debugger(Process process)
        {
            if (process == null)
                throw new ArgumentNullException("process");

            this.process = process;
            this.thread = this.process.Threads[0];
        }

        private void ProcessThreadContext(int threadId, ContextFlags flag, ThreadContextHandler handler)
        {
            if (handler == null)
                throw new ArgumentNullException("handler");

            var context = new CONTEXT { ContextFlags = flag };

            var hThread = OpenThread(0x1F03FF, false, thread.Id);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception();

            if (SuspendThread(hThread) == 0xFFFFFFFF)
                throw new Win32Exception();

            if (!GetThreadContext(hThread, ref context))
                throw new Win32Exception();

            handler(ref context);

            if (!SetThreadContext(hThread, ref context))
                throw new Win32Exception();

            if (ResumeThread(hThread) == 0xFFFFFFFF)
                throw new Win32Exception();
        }

        public void Run()
        {
            if (!DebugActiveProcess(process.Id))
                throw new Win32Exception();

            DebugSetProcessKillOnExit(false);
            var debugEvent = new DEBUG_EVENT();

            while (isDebugging)
            {
                uint dbgStatus = 0x80010001; // DBG_EXCEPTION_NOT_HANDLED

                if (!WaitForDebugEvent(ref debugEvent, 0xFFFFFFFF))
                    throw new Win32Exception();

                if (debugEvent.IsProcessStoped)
                    isDebugging = false;
                else if (debugEvent.IsSingleStep)
                {
                    ProcessThreadContext(debugEvent.ThreadId, ContextFlags.Full, (ref CONTEXT context) => {
                        if (this.thread.Id == debugEvent.ThreadId && breakpoints.ContainsKey(context.Eip))
                        {
                            breakpoints[context.Eip](process, context); // exec handler
                        }
                        context.EFlags |= 0x10000;
                    });
                    dbgStatus = 0x00010002; // DBG_CONTINUE
                }

                if (!WinApi.ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, dbgStatus))
                    throw new Win32Exception();
            }

            Console.WriteLine("Exit from debugger");
        }

        public void SetBreakPoint(uint address, DebugExceptionHandler handler)
        {
            if (address == 0u)
                throw new ArgumentNullException("address");

            if (handler == null)
                throw new ArgumentNullException("handler");

            ProcessThreadContext(thread.Id, ContextFlags.DebugRegisters, (ref CONTEXT context) => {
                int index = 0;
                for (; index < 4; ++index)
                {
                    int mask = 1 << (index * 2);
                    if ((context.Dr7 & mask) == 0)
                        break;
                }

                if (index >= 4)
                    throw new Exception("All hardware breakpoint registers are already being used");

                switch (index)
                {
                    case 0: context.Dr0 = address; break;
                    case 1: context.Dr1 = address; break;
                    case 2: context.Dr2 = address; break;
                    case 3: context.Dr3 = address; break;
                    default: throw new Exception("index has bogus value!");
                }

                context.Dr7 |= 1u << (index * 2);
                breakpoints[address] = handler;
            });
        }

        public void RemoveBreakPoint()
        {
            ProcessThreadContext(thread.Id, ContextFlags.DebugRegisters, (ref CONTEXT context) => {
                context.Dr0 = 0u;
                context.Dr1 = 0u;
                context.Dr2 = 0u;
                context.Dr3 = 0u;
                context.Dr7 = 0u;
            });
            breakpoints.Clear();
        }

        public void Stop()
        {
            RemoveBreakPoint();
            isDebugging = false;
        }
    }
}