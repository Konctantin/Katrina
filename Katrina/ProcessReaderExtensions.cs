using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Katrina
{
    public static class ProcessReaderExtensions
    {
        public static T Read<T>(this Process process, IntPtr address) where T : struct
        {
            var result = new byte[Marshal.SizeOf(typeof(T))];
            WinApi.ReadProcessMemory(process.Handle, address, result, new IntPtr(result.Length), IntPtr.Zero);
            var handle = GCHandle.Alloc(result, GCHandleType.Pinned);
            T returnObject = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return returnObject;
        }

        public static byte[] ReadBytes(this Process process, IntPtr address, int count)
        {
            var result = new byte[count];
            WinApi.ReadProcessMemory(process.Handle, address, result, new IntPtr(result.Length), IntPtr.Zero);
            return result;
        }

        public static IntPtr Rebase(this Process process, long offset)
        {
            return new IntPtr(offset + process.MainModule.BaseAddress.ToInt64());
        }
    }
}
