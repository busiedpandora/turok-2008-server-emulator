using System;
using System.IO;
using System.Text;

namespace TurokServer
{
    // Console + rotating log files (server_*.log): a new file when the current one reaches
    // Config.LogMaxMB, keeping only the newest Config.LogKeepFiles files.
    public static class Log
    {
        static StreamWriter file;
        static string directory;
        static long written;
        static readonly object sync = new object();

        public static void Open(string dir)
        {
            lock (sync)
            {
                directory = dir;
                Directory.CreateDirectory(dir);
                NewFile();
                Cleanup();
            }
        }

        static void NewFile()
        {
            if (file != null) { file.Dispose(); file = null; }
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string path = Path.Combine(directory, "server_" + stamp + ".log");
            for (int n = 1; File.Exists(path); n++)
                path = Path.Combine(directory, "server_" + stamp + "_" + n + ".log");
            file = new StreamWriter(path, false, Encoding.UTF8);
            file.AutoFlush = true;
            written = 0;
            string line = Stamp() + " [LOG] Log file: " + path;
            Console.WriteLine(line);
            file.WriteLine(line);
        }

        static void Cleanup()
        {
            try
            {
                string[] files = Directory.GetFiles(directory, "server_*.log");
                Array.Sort(files, StringComparer.Ordinal);
                for (int i = 0; i < files.Length - Math.Max(1, Config.LogKeepFiles); i++)
                    File.Delete(files[i]);
            }
            catch (Exception ex) { Console.WriteLine("log cleanup failed: " + ex.Message); }
        }

        static string Stamp() { return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"); }

        public static void Write(string source, string message)
        {
            string line = Stamp() + " [" + source + "] " + message;
            lock (sync)
            {
                Console.WriteLine(line);
                if (file == null) return;
                file.WriteLine(line);
                written += line.Length + 2;
                if (written > (long)Config.LogMaxMB * 1024 * 1024)
                {
                    NewFile();
                    Cleanup();
                }
            }
        }

        // Packet-level trace, disabled with LogPackets=false.
        public static void Packet(string source, string message)
        {
            if (Config.LogPackets) Write(source, message);
        }

        public static string Hex(byte[] b)
        {
            return b == null ? "" : Hex(b, 0, b.Length);
        }

        public static string Hex(byte[] b, int offset, int count)
        {
            StringBuilder sb = new StringBuilder(count * 3);
            for (int i = 0; i < count; i++) sb.Append(b[offset + i].ToString("X2")).Append(' ');
            return sb.ToString().TrimEnd();
        }
    }
}
