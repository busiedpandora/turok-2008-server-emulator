// Disasm <image> <hexVA> [maxInstr]  - disassembles a function from a memory image (base 0x400000)
// Disasm <image> xref <hexVA>         - finds instructions referencing an address (call/jmp/push/mov imm)
using System;
using System.IO;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

static class Disasm
{
    const ulong Base = 0x400000;
    static byte[] img;

    static int Main(string[] a)
    {
        img = File.ReadAllBytes(a[0]);
        if (a[1] == "xref") { Xref(Convert.ToUInt64(a[2], 16), a.Length > 3 ? Convert.ToUInt64(a[3], 16) : 0x401000, a.Length > 4 ? Convert.ToUInt64(a[4], 16) : 0xC00000); return 0; }
        ulong va = Convert.ToUInt64(a[1], 16);
        if (a.Length > 2 && a[2].StartsWith("to"))
        {
            DumpRange(va, Convert.ToUInt64(a[2].Substring(2), 16));
            return 0;
        }
        int max = a.Length > 2 ? int.Parse(a[2]) : 300;
        Dump(va, max);
        return 0;
    }

    static void Dump(ulong va, int max)
    {
        var reader = new ByteArrayCodeReader(img, (int)(va - Base), img.Length - (int)(va - Base));
        var dec = Decoder.Create(32, reader);
        dec.IP = va;
        var fmt = new MasmFormatter();
        var o = new StringOutput();
        for (int i = 0; i < max; i++)
        {
            Instruction ins = dec.Decode();
            string text = ins.ToString();
            string note = Annotate(ins);
            Console.WriteLine(ins.IP.ToString("X8") + "  " + text + note);
            if (ins.FlowControl == FlowControl.Return) break;
            if (ins.Code == Code.Int3) break;
        }
    }

    static void DumpRange(ulong va, ulong end)
    {
        var reader = new ByteArrayCodeReader(img, (int)(va - Base), (int)(end - va));
        var dec = Decoder.Create(32, reader);
        dec.IP = va;
        while (dec.IP < end)
        {
            Instruction ins = dec.Decode();
            Console.WriteLine(ins.IP.ToString("X8") + "  " + ins.ToString() + Annotate(ins));
        }
    }

    static string Annotate(Instruction ins)
    {
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < ins.OpCount; k++)
        {
            ulong v = 0;
            OpKind kind = ins.GetOpKind(k);
            if (kind == OpKind.Immediate32 || kind == OpKind.Immediate8to32) v = ins.GetImmediate(k);
            else if (kind == OpKind.Memory && ins.MemoryBase == Register.None) v = ins.MemoryDisplacement64;
            if (v < Base + 0x1000 || v >= Base + (ulong)img.Length) continue;
            string s = AsciiAt(v);
            if (s != null) sb.Append("    ; \"" + s + "\"");
            else
            {
                string w = Utf16At(v);
                if (w != null) sb.Append("    ; L\"" + w + "\"");
            }
        }
        return sb.ToString();
    }

    static string AsciiAt(ulong va)
    {
        int p = (int)(va - Base);
        StringBuilder sb = new StringBuilder();
        while (p < img.Length && img[p] >= 0x20 && img[p] < 0x7F && sb.Length < 80) sb.Append((char)img[p++]);
        return sb.Length >= 4 && p < img.Length && img[p] == 0 ? sb.ToString() : null;
    }

    static string Utf16At(ulong va)
    {
        int p = (int)(va - Base);
        StringBuilder sb = new StringBuilder();
        while (p + 1 < img.Length && img[p] >= 0x20 && img[p] < 0x7F && img[p + 1] == 0 && sb.Length < 80) { sb.Append((char)img[p]); p += 2; }
        return sb.Length >= 4 ? sb.ToString() : null;
    }

    static void Xref(ulong target, ulong from, ulong to)
    {
        var reader = new ByteArrayCodeReader(img, (int)(from - Base), (int)(to - from));
        var dec = Decoder.Create(32, reader);
        dec.IP = from;
        var fmt = new MasmFormatter();
        var o = new StringOutput();
        while (dec.IP < to)
        {
            Instruction ins = dec.Decode();
            bool hit = false;
            if (ins.IsCallNear || ins.IsJmpNear || ins.IsJccShortOrNear) hit = ins.NearBranchTarget == target;
            for (int k = 0; k < ins.OpCount && !hit; k++)
            {
                OpKind kind = ins.GetOpKind(k);
                if ((kind == OpKind.Immediate32 || kind == OpKind.Immediate8to32) && ins.GetImmediate(k) == target) hit = true;
                if (kind == OpKind.Memory && ins.MemoryDisplacement64 == target) hit = true;
            }
            if (hit) Console.WriteLine(ins.IP.ToString("X8") + "  " + ins.ToString());
        }
    }
}

