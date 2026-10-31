// PacketProbe - Step 1 of the Turok 2008 server emulator.
//
// Listens on the Rendez-Vous ports used by Turok (PC), decodes PRUDP v0
// packets, verifies the checksum derived from the access key, answers the
// connection handshake (SYN / CONNECT), ACKs DATA packets and prints the
// decrypted RMC request so we can see what the game asks for first.
//
// Written for C# 5 so it compiles with the csc.exe bundled with Windows
// (.NET Framework 4.x); see build.bat.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace TurokProbe
{
    static class Program
    {
        static string AccessKey = "gTy3mT5s";
        static readonly byte[] Rc4Key = Encoding.ASCII.GetBytes("CD&ML");
        static byte KeySum;
        static StreamWriter logFile;
        static readonly object logLock = new object();
        static uint nextConnSig = 0x00011000;
        static readonly Dictionary<string, Conn> conns = new Dictionary<string, Conn>();

        class Conn
        {
            public uint ServerSig;   // what we gave the client in SYN-ACK
            public uint ClientSig;   // what the client sent in CONNECT
            public byte ChecksumSetting;
        }

        static readonly string[] StreamNames = { "Unused", "DO", "RV", "OldRVSec", "SBMGMT", "NAT", "SessionDiscovery", "NATEcho", "Routing", "Game", "RVSecure", "Relay" };
        static readonly string[] TypeNames = { "SYN", "CONNECT", "DATA", "DISCONNECT", "PING", "NATPING", "T6", "T7" };

        static readonly Dictionary<int, string> Protocols = new Dictionary<int, string>
        {
            {0x03, "NATTraversal"}, {0x0A, "Authentication"}, {0x0B, "Secure"}, {0x0E, "Notification"},
            {0x14, "Friends"}, {0x15, "MatchMaking"}, {0x18, "PersistentStore"}, {0x19, "AccountManagement"},
            {0x1B, "MessageDelivery"}, {0x1F, "News"}
        };

        static int Main(string[] args)
        {
            int[] ports = { 30720, 9103 };
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--key" && i + 1 < args.Length) AccessKey = args[++i];
                else if (args[i] == "--ports" && i + 1 < args.Length)
                {
                    string[] parts = args[++i].Split(',');
                    ports = new int[parts.Length];
                    for (int j = 0; j < parts.Length; j++) ports[j] = int.Parse(parts[j]);
                }
            }

            int sum = 0;
            foreach (byte b in Encoding.ASCII.GetBytes(AccessKey)) sum += b;
            KeySum = (byte)sum;

            string logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            string logPath = Path.Combine(logDir, "probe_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
            logFile = new StreamWriter(logPath, false, Encoding.UTF8);
            logFile.AutoFlush = true;

            Log("Turok PacketProbe");
            Log("Access key: " + AccessKey + "  checksum setting (sum of key bytes): 0x" + KeySum.ToString("X2"));
            Log("Log file  : " + logPath);

            foreach (int port in ports)
            {
                UdpClient udp;
                try
                {
                    udp = new UdpClient(new IPEndPoint(IPAddress.Any, port));
                }
                catch (Exception ex)
                {
                    Log("!! Cannot bind UDP " + port + ": " + ex.Message);
                    continue;
                }
                // Ignore ICMP "port unreachable" resets on Windows.
                const int SIO_UDP_CONNRESET = -1744830452;
                udp.Client.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null);
                int p = port;
                Thread t = new Thread(() => Listen(udp, p));
                t.IsBackground = true;
                t.Start();
                Log("Listening on UDP " + port);
            }

            Log("Waiting for packets. Press Ctrl+C to stop.");
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }

        static void Listen(UdpClient udp, int port)
        {
            while (true)
            {
                IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                byte[] data;
                try { data = udp.Receive(ref ep); }
                catch (Exception ex) { Log("!! Receive error on " + port + ": " + ex.Message); continue; }
                try { Handle(udp, port, ep, data); }
                catch (Exception ex) { Log("!! Handler error: " + ex); }
            }
        }

        // ---------------------------------------------------------------- PRUDP

        class Packet
        {
            public byte Src, Dst, TypeFlags, Session;
            public uint Signature, ConnSig;
            public ushort Seq;
            public byte Part;
            public byte[] Payload;
            public byte Checksum;
            public int Size;

            public int Type { get { return TypeFlags & 7; } }
            public int Flags { get { return TypeFlags >> 3; } }
            public bool HasFlag(int f) { return (Flags & f) != 0; }
        }

        const int FLAG_ACK = 1, FLAG_RELIABLE = 2, FLAG_NEED_ACK = 4, FLAG_HAS_SIZE = 8;
        const int SYN = 0, CONNECT = 1, DATA = 2, DISCONNECT = 3, PING = 4, NATPING = 5;

        static Packet Parse(byte[] d, int offset)
        {
            Packet p = new Packet();
            int o = offset;
            p.Src = d[o++]; p.Dst = d[o++]; p.TypeFlags = d[o++]; p.Session = d[o++];
            p.Signature = BitConverter.ToUInt32(d, o); o += 4;
            p.Seq = BitConverter.ToUInt16(d, o); o += 2;
            if (p.Type == SYN || p.Type == CONNECT) { p.ConnSig = BitConverter.ToUInt32(d, o); o += 4; }
            if (p.Type == DATA) p.Part = d[o++];
            int len;
            if (p.HasFlag(FLAG_HAS_SIZE)) { len = BitConverter.ToUInt16(d, o); o += 2; }
            else len = d.Length - o - 1;
            if (len < 0) len = 0;
            p.Payload = new byte[len];
            Array.Copy(d, o, p.Payload, 0, len); o += len;
            p.Checksum = d[o++];
            p.Size = o - offset;
            return p;
        }

        static byte[] Build(Packet p, byte setting)
        {
            MemoryStream m = new MemoryStream();
            m.WriteByte(p.Src); m.WriteByte(p.Dst); m.WriteByte(p.TypeFlags); m.WriteByte(p.Session);
            m.Write(BitConverter.GetBytes(p.Signature), 0, 4);
            m.Write(BitConverter.GetBytes(p.Seq), 0, 2);
            if (p.Type == SYN || p.Type == CONNECT) m.Write(BitConverter.GetBytes(p.ConnSig), 0, 4);
            if (p.Type == DATA) m.WriteByte(p.Part);
            byte[] pl = p.Payload ?? new byte[0];
            if (p.HasFlag(FLAG_HAS_SIZE)) m.Write(BitConverter.GetBytes((ushort)pl.Length), 0, 2);
            m.Write(pl, 0, pl.Length);
            byte[] body = m.ToArray();
            byte[] result = new byte[body.Length + 1];
            Array.Copy(body, result, body.Length);
            result[body.Length] = Checksum(body, 0, body.Length, setting);
            return result;
        }

        // Same algorithm as QuazalWV QPacket.MakeChecksum.
        static byte Checksum(byte[] data, int offset, int length, byte setting)
        {
            uint tmp = 0;
            for (int i = 0; i < length / 4; i++)
                tmp += BitConverter.ToUInt32(data, offset + i * 4);
            int leftOver = length & 3;
            int pos = offset + length - leftOver;
            int processed = 0;
            byte t2 = 0, t3 = 0, t4;
            if (leftOver >= 2) { processed = 2; t2 = data[pos]; t3 = data[pos + 1]; pos += 2; }
            if (processed >= leftOver) t4 = setting;
            else t4 = (byte)(setting + data[pos]);
            return (byte)((byte)(tmp >> 24) + (byte)(tmp >> 16) + (byte)(tmp >> 8) + (byte)tmp + t2 + t3 + t4);
        }

        static string VPort(byte b)
        {
            int t = b >> 4;
            string name = t < StreamNames.Length ? StreamNames[t] : ("Type" + t);
            return name + ":" + (b & 0xF);
        }

        static string FlagString(Packet p)
        {
            StringBuilder sb = new StringBuilder();
            if (p.HasFlag(FLAG_ACK)) sb.Append("ACK ");
            if (p.HasFlag(FLAG_RELIABLE)) sb.Append("RELIABLE ");
            if (p.HasFlag(FLAG_NEED_ACK)) sb.Append("NEED_ACK ");
            if (p.HasFlag(FLAG_HAS_SIZE)) sb.Append("HAS_SIZE ");
            if (p.HasFlag(16)) sb.Append("UNK16 ");
            return sb.ToString().Trim();
        }

        // ---------------------------------------------------------------- handling

        static void Handle(UdpClient udp, int port, IPEndPoint ep, byte[] data)
        {
            Log("");
            Log("<<< " + ep + " -> :" + port + "  " + data.Length + " bytes");
            Log("    raw: " + Hex(data, 0, data.Length));

            if (data.Length >= 2 && data[0] == 0xEA && data[1] == 0xD0)
            {
                Log("    !! PRUDP v1 magic (EA D0) detected. This probe only decodes v0. Report this.");
                return;
            }
            if (data.Length < 10)
            {
                Log("    (too short for a PRUDP v0 header)");
                return;
            }

            int offset = 0;
            while (offset < data.Length)
            {
                Packet p;
                try { p = Parse(data, offset); }
                catch (Exception ex) { Log("    !! parse failed: " + ex.Message); return; }

                byte withKey = Checksum(data, offset, p.Size - 1, KeySum);
                byte withZero = Checksum(data, offset, p.Size - 1, 0);
                string ck;
                byte setting;
                if (p.Checksum == withKey) { ck = "OK (access-key sum 0x" + KeySum.ToString("X2") + ")"; setting = KeySum; }
                else if (p.Checksum == withZero) { ck = "OK (setting 0x00)"; setting = 0; }
                else
                {
                    ck = "MISMATCH got 0x" + p.Checksum.ToString("X2") + " key=0x" + withKey.ToString("X2") + " zero=0x" + withZero.ToString("X2");
                    setting = KeySum;
                }

                Log("    " + TypeNames[p.Type] + " [" + FlagString(p) + "]  " + VPort(p.Src) + " -> " + VPort(p.Dst) +
                    "  session=0x" + p.Session.ToString("X2") + " sig=0x" + p.Signature.ToString("X8") + " seq=" + p.Seq +
                    (p.Type == SYN || p.Type == CONNECT ? " connSig=0x" + p.ConnSig.ToString("X8") : "") +
                    (p.Type == DATA ? " part=" + p.Part : "") + "  payload=" + p.Payload.Length + "  checksum " + ck);

                Respond(udp, ep, p, setting);
                offset += p.Size;
                if (offset < data.Length) Log("    (another packet follows in the same datagram)");
            }
        }

        static void Respond(UdpClient udp, IPEndPoint ep, Packet p, byte setting)
        {
            string key = ep.ToString();
            Conn c;
            conns.TryGetValue(key, out c);

            if (p.Type == SYN && !p.HasFlag(FLAG_ACK))
            {
                c = new Conn();
                c.ServerSig = nextConnSig++;
                c.ChecksumSetting = setting;
                conns[key] = c;
                Packet r = Reply(p, SYN, FLAG_ACK);
                r.Signature = p.Signature;
                r.ConnSig = c.ServerSig;
                Send(udp, ep, r, setting, "SYN-ACK");
                return;
            }
            if (c == null)
            {
                Log("    (no handshake seen for this endpoint, not answering)");
                return;
            }

            if (p.Type == CONNECT && !p.HasFlag(FLAG_ACK))
            {
                c.ClientSig = p.ConnSig;
                if (p.Payload.Length > 0)
                    Log("    CONNECT carries a " + p.Payload.Length + "-byte payload (Kerberos ticket check, used on the secure server).");
                Packet r = Reply(p, CONNECT, FLAG_ACK);
                r.Signature = c.ClientSig;
                r.ConnSig = c.ServerSig;
                Send(udp, ep, r, setting, "CONNECT-ACK");
                return;
            }

            if (p.Type == DATA)
            {
                if (p.HasFlag(FLAG_ACK)) return;
                DecodeData(p);
                if (p.HasFlag(FLAG_NEED_ACK) || p.HasFlag(FLAG_RELIABLE))
                {
                    Packet r = Reply(p, DATA, FLAG_ACK);
                    r.Signature = c.ClientSig;
                    r.Part = p.Part;
                    Send(udp, ep, r, setting, "DATA-ACK");
                }
                return;
            }

            if (p.Type == PING && !p.HasFlag(FLAG_ACK))
            {
                Packet r = Reply(p, PING, FLAG_ACK);
                r.Signature = c.ClientSig;
                Send(udp, ep, r, setting, "PING-ACK");
                return;
            }

            if (p.Type == DISCONNECT)
            {
                Packet r = Reply(p, DISCONNECT, FLAG_ACK);
                r.Signature = c.ClientSig;
                Send(udp, ep, r, setting, "DISCONNECT-ACK");
                conns.Remove(key);
            }
        }

        static Packet Reply(Packet p, int type, int flags)
        {
            Packet r = new Packet();
            r.Src = p.Dst; r.Dst = p.Src;
            r.TypeFlags = (byte)(type | (flags << 3));
            r.Session = p.Session;
            r.Seq = p.Seq;
            r.Payload = new byte[0];
            return r;
        }

        static void Send(UdpClient udp, IPEndPoint ep, Packet r, byte setting, string what)
        {
            byte[] buf = Build(r, setting);
            udp.Send(buf, buf.Length, ep);
            Log(">>> " + what + " to " + ep + ": " + Hex(buf, 0, buf.Length));
        }

        // ---------------------------------------------------------------- payload

        static void DecodeData(Packet p)
        {
            if (p.Payload.Length == 0) return;
            Log("    payload (encrypted): " + Hex(p.Payload, 0, p.Payload.Length));
            byte[] dec = Rc4(Rc4Key, p.Payload);
            Log("    payload (RC4 CD&ML): " + Hex(dec, 0, dec.Length));

            byte[] rmc;
            if (dec[0] == 0)
            {
                rmc = new byte[dec.Length - 1];
                Array.Copy(dec, 1, rmc, 0, rmc.Length);
                Log("    compression: none");
            }
            else
            {
                Log("    compression: zlib (ratio byte " + dec[0] + ")");
                try { rmc = Inflate(dec, 1); }
                catch (Exception ex) { Log("    !! zlib inflate failed: " + ex.Message); return; }
            }
            Log("    RMC bytes: " + Hex(rmc, 0, rmc.Length));
            DescribeRmc(rmc);
        }

        static void DescribeRmc(byte[] b)
        {
            if (b.Length < 13) { Log("    (RMC message too short)"); return; }
            int o = 0;
            uint size = BitConverter.ToUInt32(b, o); o += 4;
            byte proto = b[o++];
            bool isRequest = (proto & 0x80) != 0;
            int protoId = proto & 0x7F;
            if (protoId == 0x7F) { protoId = BitConverter.ToUInt16(b, o); o += 2; }
            string pname;
            if (!Protocols.TryGetValue(protoId, out pname)) pname = "Unknown";
            if (isRequest)
            {
                uint callId = BitConverter.ToUInt32(b, o); o += 4;
                uint methodId = BitConverter.ToUInt32(b, o); o += 4;
                Log("    RMC REQUEST size=" + size + " protocol=0x" + protoId.ToString("X2") + " (" + pname + ") callId=" + callId + " method=" + methodId);
            }
            else
            {
                Log("    RMC RESPONSE size=" + size + " protocol=0x" + protoId.ToString("X2") + " (" + pname + ") success=" + b[o]);
            }
            Log("    parameters: " + Hex(b, o, b.Length - o));
            List<string> strs = QuazalStrings(b, o);
            if (strs.Count > 0) Log("    strings found: \"" + string.Join("\", \"", strs.ToArray()) + "\"");
        }

        // Quazal strings are u16 length (including the trailing NUL) + ASCII bytes.
        static List<string> QuazalStrings(byte[] b, int start)
        {
            List<string> res = new List<string>();
            int o = start;
            while (o + 2 < b.Length)
            {
                int len = BitConverter.ToUInt16(b, o);
                if (len >= 2 && o + 2 + len <= b.Length && b[o + 2 + len - 1] == 0)
                {
                    bool ok = true;
                    for (int i = 0; i < len - 1; i++)
                        if (b[o + 2 + i] < 0x20 || b[o + 2 + i] > 0x7E) { ok = false; break; }
                    if (ok)
                    {
                        res.Add(Encoding.ASCII.GetString(b, o + 2, len - 1));
                        o += 2 + len;
                        continue;
                    }
                }
                o++;
            }
            return res;
        }

        static byte[] Rc4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + key[i % key.Length] + s[i]) & 255;
                byte t = s[i]; s[i] = s[j]; s[j] = t;
            }
            byte[] o = new byte[data.Length];
            for (int k = 0, i = 0, j = 0; k < data.Length; k++)
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;
                byte t = s[i]; s[i] = s[j]; s[j] = t;
                o[k] = (byte)(data[k] ^ s[(s[i] + s[j]) & 255]);
            }
            return o;
        }

        // zlib = 2-byte header + raw deflate + adler32; DeflateStream handles the middle part.
        static byte[] Inflate(byte[] data, int offset)
        {
            MemoryStream input = new MemoryStream(data, offset + 2, data.Length - offset - 2);
            using (DeflateStream ds = new DeflateStream(input, CompressionMode.Decompress))
            {
                MemoryStream output = new MemoryStream();
                ds.CopyTo(output);
                return output.ToArray();
            }
        }

        // ---------------------------------------------------------------- utils

        static string Hex(byte[] b, int offset, int count)
        {
            StringBuilder sb = new StringBuilder(count * 3);
            for (int i = 0; i < count; i++) sb.Append(b[offset + i].ToString("X2")).Append(' ');
            return sb.ToString().TrimEnd();
        }

        static void Log(string s)
        {
            string line = DateTime.Now.ToString("HH:mm:ss.fff") + "  " + s;
            lock (logLock)
            {
                Console.WriteLine(line);
                if (logFile != null) logFile.WriteLine(line);
            }
        }
    }
}
