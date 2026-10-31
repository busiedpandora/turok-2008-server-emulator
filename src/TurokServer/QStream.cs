using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TurokServer
{
    // Reader/writer for Quazal serialized types (little endian).
    public class QReader
    {
        readonly byte[] data;
        int pos;

        public QReader(byte[] data) : this(data, 0) { }
        public QReader(byte[] data, int offset) { this.data = data; pos = offset; }

        public int Position { get { return pos; } }
        public int Remaining { get { return data.Length - pos; } }

        void Need(int n)
        {
            if (pos + n > data.Length) throw new EndOfStreamException("need " + n + " bytes at " + pos + ", have " + Remaining);
        }

        public byte U8() { Need(1); return data[pos++]; }
        public ushort U16() { Need(2); ushort v = BitConverter.ToUInt16(data, pos); pos += 2; return v; }
        public uint U32() { Need(4); uint v = BitConverter.ToUInt32(data, pos); pos += 4; return v; }
        public ulong U64() { Need(8); ulong v = BitConverter.ToUInt64(data, pos); pos += 8; return v; }
        public bool Bool() { return U8() != 0; }

        public byte[] Bytes(int n) { Need(n); byte[] b = new byte[n]; Array.Copy(data, pos, b, 0, n); pos += n; return b; }
        public byte[] Buffer() { return Bytes((int)U32()); }
        public byte[] QBuffer() { return Bytes(U16()); }
        public byte[] Rest() { return Bytes(Remaining); }

        public string String()
        {
            int len = U16();
            if (len == 0) return "";
            byte[] b = Bytes(len);
            int n = len;
            if (b[n - 1] == 0) n--;
            return Encoding.ASCII.GetString(b, 0, n);
        }

        public List<string> StringList()
        {
            uint count = U32();
            List<string> l = new List<string>();
            for (uint i = 0; i < count; i++) l.Add(String());
            return l;
        }
    }

    public class QWriter
    {
        readonly MemoryStream m = new MemoryStream();

        public QWriter U8(byte v) { m.WriteByte(v); return this; }
        public QWriter U16(ushort v) { m.Write(BitConverter.GetBytes(v), 0, 2); return this; }
        public QWriter U32(uint v) { m.Write(BitConverter.GetBytes(v), 0, 4); return this; }
        public QWriter U64(ulong v) { m.Write(BitConverter.GetBytes(v), 0, 8); return this; }
        public QWriter Bool(bool v) { return U8((byte)(v ? 1 : 0)); }
        public QWriter Bytes(byte[] b) { m.Write(b, 0, b.Length); return this; }
        public QWriter Buffer(byte[] b) { U32((uint)b.Length); return Bytes(b); }
        public QWriter QBuffer(byte[] b) { U16((ushort)b.Length); return Bytes(b); }

        public QWriter String(string s)
        {
            if (s == null) s = "";
            byte[] b = Encoding.ASCII.GetBytes(s);
            U16((ushort)(b.Length + 1));
            Bytes(b);
            return U8(0);
        }

        public QWriter StringList(IList<string> l)
        {
            U32((uint)l.Count);
            foreach (string s in l) String(s);
            return this;
        }

        public byte[] ToArray() { return m.ToArray(); }
        public int Length { get { return (int)m.Length; } }
    }
}
