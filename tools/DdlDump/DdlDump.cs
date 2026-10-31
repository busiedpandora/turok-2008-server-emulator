// DdlDump - reads the memory of the running TurokGame.exe (the file on disk is packed),
// finds Quazal DDL blobs (magic CD 65 23 12) and prints protocols, methods, parameters and
// classes. Parser ported from NamespaceParserWV (Ghost Recon Future Soldier research).
//
// Usage: DdlDump.exe [processName] [outputFile]
//        defaults: TurokGame  ddl.txt

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

static class DdlDump
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, IntPtr len);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    const uint PROCESS_QUERY_INFORMATION = 0x400, PROCESS_VM_READ = 0x10;
    const uint MEM_COMMIT = 0x1000, PAGE_GUARD = 0x100, PAGE_NOACCESS = 0x01;

    static StringBuilder sb = new StringBuilder();

    static int Main(string[] args)
    {
        string name = args.Length > 0 ? args[0] : "TurokGame";
        string outFile = args.Length > 1 ? args[1] : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ddl.txt");
        Process[] ps = Process.GetProcessesByName(name);
        if (ps.Length == 0) { Console.WriteLine("Process " + name + " not running."); return 1; }
        Process p = ps[0];
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
        if (h == IntPtr.Zero) { Console.WriteLine("OpenProcess failed: " + Marshal.GetLastWin32Error()); return 1; }

        // Always save the unpacked main module image next to the output, for string/code analysis.
        try
        {
            ProcessModule mod = p.MainModule;
            long baseAddr = mod.BaseAddress.ToInt64();
            byte[] img = new byte[mod.ModuleMemorySize];
            long a = baseAddr;
            while (a < baseAddr + img.Length)
            {
                MEMORY_BASIC_INFORMATION mi;
                if (VirtualQueryEx(h, new IntPtr(a), out mi, new IntPtr(Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))) == IntPtr.Zero) break;
                long rs = Math.Min(mi.RegionSize.ToInt64(), baseAddr + img.Length - a);
                if (mi.State == MEM_COMMIT && (mi.Protect & PAGE_GUARD) == 0 && (mi.Protect & PAGE_NOACCESS) == 0)
                {
                    byte[] tmp = new byte[rs];
                    IntPtr rd;
                    if (ReadProcessMemory(h, new IntPtr(a), tmp, new IntPtr(rs), out rd))
                        Array.Copy(tmp, 0, img, a - baseAddr, rd.ToInt64());
                }
                a += rs;
            }
            string imgPath = Path.ChangeExtension(outFile, ".image.bin");
            File.WriteAllBytes(imgPath, img);
            Console.WriteLine("Main module image (" + (img.Length / 1024) + " KB, base 0x" + baseAddr.ToString("X") + ") saved to " + imgPath);
        }
        catch (Exception ex) { Console.WriteLine("Could not dump main module: " + ex.Message); }

        int blobs = 0;
        long scanned = 0;
        HashSet<string> seen = new HashSet<string>();
        long addr = 0;
        long max = IntPtr.Size == 4 ? 0x7FFF0000L : 0x7FFFFFFF0000L;
        while (addr < max)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(h, new IntPtr(addr), out mbi, new IntPtr(Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))) == IntPtr.Zero) break;
            long size = mbi.RegionSize.ToInt64();
            if (size <= 0) break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 && (mbi.Protect & PAGE_NOACCESS) == 0 && size < 512L * 1024 * 1024)
            {
                byte[] buf = new byte[size];
                IntPtr read;
                if (ReadProcessMemory(h, mbi.BaseAddress, buf, new IntPtr(size), out read) && read.ToInt64() > 0)
                {
                    scanned += read.ToInt64();
                    int n = (int)read.ToInt64();
                    for (int i = 0; i + 4 <= n; i += 4)
                    {
                        if (buf[i] != 0xCD || buf[i + 1] != 0x65 || buf[i + 2] != 0x23 || buf[i + 3] != 0x12) continue;
                        int startLen = sb.Length;
                        sb.AppendLine("==== DDL blob at 0x" + (addr + i).ToString("X"));
                        MemoryStream m = new MemoryStream(buf, i + 4 + 17, n - i - 4 - 17);
                        try { Parse(m, 0); blobs++; }
                        catch (Exception ex) { sb.AppendLine("!! parse stopped: " + ex.Message); }
                        // drop exact duplicates (same blob mapped twice)
                        string chunk = sb.ToString(startLen, sb.Length - startLen);
                        string body = chunk.Substring(chunk.IndexOf('\n') + 1);
                        if (!seen.Add(body)) sb.Length = startLen;
                    }
                }
            }
            addr = mbi.BaseAddress.ToInt64() + size;
        }
        CloseHandle(h);
        File.WriteAllText(outFile, sb.ToString());
        Console.WriteLine("Scanned " + (scanned / 1024 / 1024) + " MB, " + blobs + " DDL blob(s). Output: " + outFile);
        return 0;
    }

    // ------------------------------------------------------------------ parser (big endian)

    static uint ReadU32(Stream s)
    {
        uint r = 0;
        for (int i = 0; i < 4; i++)
        {
            int b = s.ReadByte();
            if (b < 0) throw new EndOfStreamException();
            r = (r << 8) | (byte)b;
        }
        return r;
    }

    static int ReadU8(Stream s)
    {
        int b = s.ReadByte();
        if (b < 0) throw new EndOfStreamException();
        return b;
    }

    static string ReadString(Stream s)
    {
        uint len = ReadU32(s);
        if (len > 1000) throw new InvalidDataException("string too long (" + len + ")");
        StringBuilder r = new StringBuilder();
        for (int i = 0; i < len; i++) r.Append((char)ReadU8(s));
        return r.ToString().TrimEnd('\0');
    }

    static void Log(int depth, string s) { sb.Append(new string(' ', depth * 2)).AppendLine(s); }

    static readonly string[] ItemNames = {
        "ParseTreeItem","NameSpaceItem","Declaration","DOClassDeclaration","DatasetDeclaration","TypeDeclaration",
        "Variable","MethodDeclaration","RMC","Action","AdapterDeclaration","PropertyDeclaration","ProtocolDeclaration",
        "Parameter","ReturnValue","ClassDeclaration","TemplateDeclaration","SimpleTypeDeclaration","TemplateInstance",
        "DDLUnitDeclaration","DupSpaceDeclaration" };

    static void Parse(Stream m, int d)
    {
        uint count = ReadU32(m);
        if (count > 10000) throw new InvalidDataException("bad item count " + count);
        for (int i = 0; i < count; i++)
        {
            int type = ReadU8(m);
            switch (type)
            {
                case 3: Log(d, "DOClass"); NamespaceItem(m, d + 1); Namespace(m, d + 1); Log(d + 1, "base: " + ReadString(m)); Log(d + 1, "id: 0x" + ReadU32(m).ToString("X")); Parse(m, d + 1); break;
                case 4: Log(d, "Dataset"); NamespaceItem(m, d + 1); Namespace(m, d + 1); Parse(m, d + 1); break;
                case 6: Variable(m, d); break;
                case 8: Log(d, "RMC method"); ProtocolDecl(m, d + 1); Parse(m, d + 1); break;
                case 9: Log(d, "Action"); ProtocolDecl(m, d + 1); Parse(m, d + 1); break;
                case 0xA: Log(d, "Adapter"); Declaration(m, d + 1); break;
                case 0xB: Log(d, "Property"); NamespaceItem(m, d + 1); Namespace(m, d + 1); Log(d + 1, "0x" + ReadU32(m).ToString("X") + " 0x" + ReadU32(m).ToString("X")); break;
                case 0xC: Log(d, "Protocol"); ProtocolDecl(m, d + 1); break;
                case 0xD: Log(d, "Parameter"); Variable(m, d + 1); DeclUse(m, d + 1); Log(d + 1, "size 0x" + ReadU32(m).ToString("X") + " dir " + ReadU8(m)); break;
                case 0xE: Log(d, "ReturnValue"); Variable(m, d + 1); DeclUse(m, d + 1); Log(d + 1, "size 0x" + ReadU32(m).ToString("X")); break;
                case 0xF: Log(d, "Class"); Declaration(m, d + 1); Namespace(m, d + 1); break;
                case 0x10: Log(d, "Template"); Declaration(m, d + 1); Log(d + 1, "args " + ReadU32(m)); break;
                case 0x11: Log(d, "SimpleType"); Declaration(m, d + 1); break;
                case 0x12: Log(d, "TemplateInstance"); Declaration(m, d + 1); NamedStringList(m, d + 1); break;
                case 0x13: Log(d, "DDLUnit"); Declaration(m, d + 1); Log(d + 1, ReadString(m)); Log(d + 1, ReadString(m)); break;
                case 0x14: Log(d, "DupSpace"); Declaration(m, d + 1); break;
                default: throw new InvalidDataException("unknown item type 0x" + type.ToString("X2"));
            }
        }
    }

    static void ProtocolDecl(Stream m, int d) { Declaration(m, d); Parse(m, d); }
    static void Declaration(Stream m, int d) { NamespaceItem(m, d); Namespace(m, d); }
    static void NamespaceItem(Stream m, int d) { Log(d, "name: " + ReadString(m) + "  [" + ReadString(m) + "]"); }
    static void Namespace(Stream m, int d) { Log(d, "ns: " + ReadString(m)); Parse(m, d + 1); }

    static void Variable(Stream m, int d)
    {
        Log(d, "var " + ReadString(m) + " [" + ReadString(m) + "]");
        DeclUse(m, d + 1);
        Log(d + 1, "0x" + ReadU32(m).ToString("X"));
    }

    static void DeclUse(Stream m, int d)
    {
        int b = ReadU8(m);
        string type = b < ItemNames.Length ? ItemNames[b] : ("0x" + b.ToString("X"));
        if (b == 0x12)
        {
            Log(d, "type " + type + " " + ReadString(m) + " [" + ReadString(m) + "]");
            int count = ReadU8(m);
            for (int i = 0; i < count; i++) DeclUse(m, d + 1);
        }
        else Log(d, "type " + type + " " + ReadString(m));
    }

    static void NamedStringList(Stream m, int d)
    {
        Log(d, "list " + ReadString(m));
        uint count = ReadU32(m);
        if (count > 1000) throw new InvalidDataException("bad list count");
        for (int i = 0; i < count; i++) Log(d + 1, ReadString(m));
    }
}
