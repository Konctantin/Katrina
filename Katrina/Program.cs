using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Katrina
{
    public enum Direction : uint
    {
        CMSG = 0x47534D43,
        SMSG = 0x47534D53,
    };

    public class Program
    {
        const byte SNIFFER_ID    = 0x20;
        const ushort PKT_VERSION = 0x0301; //3.1

        static object lockObject = new object();

        static BinaryWriter writer;
        static Process process;
        static Debugger debugger;
        static WinApi.ConsoleEventDelegate consoleEventHandler;

        static bool ConsoleEventCallback(int eventType)
        {
            if (eventType == 2 || eventType == 0)
            {
                if (debugger != null)
                    debugger.Stop();
                Console.WriteLine("Quting...");
            }
            return false;
        }

        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            consoleEventHandler = new WinApi.ConsoleEventDelegate(ConsoleEventCallback);
            WinApi.SetConsoleCtrlHandler(consoleEventHandler, true);

            Console.WriteLine("Welcome to Katrina, a WoW debugger sniffer.\n");

            var processList = Process.GetProcessesByName("wow")
                    //.Concat(Process.GetProcessesByName("wow-64"))
                    .ToArray();

            if (processList.Length == 0)
            {
                Console.WriteLine("'Wow' process NOT found.");
                Console.WriteLine("Note: be sure the process which you looking for");
                Console.WriteLine("is must be a 32 bit process.");
                Console.ReadKey();
                return;
            }

            if (processList.Length > 1)
            {
                Console.WriteLine("Multiple 'Wow' processes found.");
                Console.WriteLine("Please select one which will be injected.");

                Console.ForegroundColor = ConsoleColor.Magenta;
                for (int i = 0; i < processList.Length; ++i)
                {
                    Console.WriteLine("  [{0}] PID: {1}", i, processList[i].Id);
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                while (true)
                {
                    Console.Write("Please select a process, use [index]: ");

                    uint index;
                    var line = Console.ReadLine();

                    if (!uint.TryParse(line, out index))
                    {
                        Console.WriteLine("Incorect value '{0}'", line);
                        continue;
                    }
                    // bigger than max index
                    if (index > processList.Length - 1)
                    {
                        Console.WriteLine("Your index is too big, max index is {0}.", processList.Length - 1);
                        continue;
                    }

                    // looks like all good
                    process = processList[index];
                    break;
                }
            }
            else
            {
                process = processList[0];
            }

            Console.WriteLine("Used process by PID: {0}", process.Id);

            Offsets.Load(process.MainModule.FileVersionInfo.FilePrivatePart);
            debugger = new Debugger(process);

            // offset + 1
            // skip: push ebp
            debugger.SetBreakPoint((uint)process.Rebase(Offsets.Send_2).ToInt32(), Send2);
            debugger.SetBreakPoint((uint)process.Rebase(Offsets.Recive).ToInt32(), ProcessMessage);

            // debug loop
            debugger.Run();

            if (writer != null)
            {
                writer.Flush();
                writer.Close();
            }
        }

        static void Send2(Process process, CONTEXT context)
        {
            var ptr = process.Read<IntPtr>(new IntPtr(context.Esp + Offsets.Send_ds));
            var dataStore  = process.Read<CDataStore>(ptr);
            var packet     = process.ReadBytes(dataStore.buffer, dataStore.size);
            var connection = process.Read<int>(new IntPtr(context.Esp + Offsets.Send_ds + 4));

            lock (lockObject)
            {
                DumpPacket(Direction.CMSG, connection, packet);
            }
        }

        static void ProcessMessage(Process process, CONTEXT context)
        {
            var ptr = process.Read<IntPtr>(new IntPtr(context.Esp + Offsets.Recv_ds));
            var dataStore  = process.Read<CDataStore>(ptr);
            var packet     = process.ReadBytes(dataStore.buffer, dataStore.size);
            var connection = process.Read<int>(new IntPtr(context.Esp + Offsets.Recv_ds + 4));

            lock (lockObject)
            {
                DumpPacket(Direction.SMSG, connection, packet);
            }
        }

        static void DumpPacket(Direction direction, int connectionId, byte[] packet)
        {
            if (writer == null)
            {
                var locale = "xxXX";
                if (Offsets.Locale > 0)
                {
                    locale = Encoding.ASCII.GetString(
                        process.ReadBytes(
                            process.Rebase(Offsets.Locale), 4)
                            .Reverse().ToArray()
                        );
                }

                Console.WriteLine("Detected locale: " + locale);

                var fname = string.Format("wowsniff_{0}_{1}_{2:yyyy-MM-dd_HH-mm-ss}.pkt", locale, Offsets.build, DateTime.Now);
                writer = new BinaryWriter(new FileStream(Path.Combine(Environment.CurrentDirectory, fname), FileMode.Create));

                Console.WriteLine("Sniff dump:" + fname);

                writer.Write(new[] { 'P', 'K', 'T' });  // magic
                writer.Write(PKT_VERSION);              // major.minor version
                writer.Write(SNIFFER_ID);               // sniffer id
                writer.Write(Offsets.build);            // client build
                writer.Write(locale);                   // client lang
                writer.Write(new byte[40]);             // session key
                writer.Write(DateTime.Now.Ticks);       // started time
                writer.Write(Environment.TickCount);    // started tick's
                writer.Write(0);                        // opional header length
                writer.Flush();
            }

            writer.Write((uint)direction);          // direction of the packet
            writer.Write(connectionId);             // connection id
            writer.Write(Environment.TickCount);    // timestamp of the packet
            writer.Write(0);                        // optional header length
            writer.Write(packet.Length);            // size of the packet + opcode lenght
            writer.Write(packet);                   // data
            writer.Flush();

            //Console.WriteLine("{0}: Size: {1}, Opcode: 0x{2:X4} ({2})",
            //    direction, packet.Length, BitConverter.ToInt32(packet, 0));
        }
    }
}
