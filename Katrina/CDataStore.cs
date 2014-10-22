using System;
using System.Runtime.InteropServices;

namespace Katrina
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CDataStore
    {
        public IntPtr vTable;
        public IntPtr buffer;
        public int mbase;
        public int alloc;
        public int size;
        public int read;
    }
}
