using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace TurokServer
{
    // ------------------------------------------------------------------ packet (PRUDP v0)

    public class PrudpPacket
    {
        public const int SYN = 0, CONNECT = 1, DATA = 2, DISCONNECT = 3, PING = 4, NATPING = 5;
        public const int FLAG_ACK = 1, FLAG_RELIABLE = 2, FLAG_NEED_ACK = 4, FLAG_HAS_SIZE = 8;
        static readonly string[] TypeNames = { "SYN", "CONNECT", "DATA", "DISCONNECT", "PING", "NATPING", "T6", "T7" };

        public byte Src, Dst, Session;
        public int Type, Flags;
        public uint Signature, ConnSig;
        public ushort Seq;
        public byte Part;
        public byte[] Payload = new byte[0];
        public byte Checksum;
        public int Size;
        public bool ChecksumOk;

        public bool Has(int flag) { return (Flags & flag) != 0; }

        public const int StreamOldRVSec = 3, StreamNATEcho = 7;

        // Stream type 3 (RV secure) uses the access-key checksum setting, the others use 0
        // (confirmed for NATEcho packets in a capture).
        public static byte SettingFor(byte firstByte, byte keySetting)
        {
            return (firstByte >> 4) == StreamOldRVSec ? keySetting : (byte)0;
        }

        public static PrudpPacket Parse(byte[] d, int offset, byte keySetting)
        {
            byte setting = SettingFor(d[offset], keySetting);
            PrudpPacket p = new PrudpPacket();
            int o = offset;
            p.Src = d[o++]; p.Dst = d[o++];
            byte tf = d[o++];
            p.Type = tf & 7; p.Flags = tf >> 3;
            p.Session = d[o++];
            p.Signature = BitConverter.ToUInt32(d, o); o += 4;
            p.Seq = BitConverter.ToUInt16(d, o); o += 2;
            if (p.Type == SYN || p.Type == CONNECT) { p.ConnSig = BitConverter.ToUInt32(d, o); o += 4; }
            if (p.Type == DATA) p.Part = d[o++];
            int len;
            if (p.Has(FLAG_HAS_SIZE)) { len = BitConverter.ToUInt16(d, o); o += 2; }
            else len = d.Length - o - 1;
            if (len < 0 || o + len + 1 > d.Length) throw new InvalidDataException("bad PRUDP length");
            p.Payload = new byte[len];
            Array.Copy(d, o, p.Payload, 0, len); o += len;
            p.Checksum = d[o++];
            p.Size = o - offset;
            p.ChecksumOk = ComputeChecksum(d, offset, p.Size - 1, setting) == p.Checksum;
            return p;
        }

        public byte[] Build(byte keySetting)
        {
            byte setting = SettingFor(Src, keySetting);
            MemoryStream m = new MemoryStream();
            m.WriteByte(Src); m.WriteByte(Dst);
            m.WriteByte((byte)(Type | (Flags << 3)));
            m.WriteByte(Session);
            m.Write(BitConverter.GetBytes(Signature), 0, 4);
            m.Write(BitConverter.GetBytes(Seq), 0, 2);
            if (Type == SYN || Type == CONNECT) m.Write(BitConverter.GetBytes(ConnSig), 0, 4);
            if (Type == DATA) m.WriteByte(Part);
            if (Has(FLAG_HAS_SIZE)) m.Write(BitConverter.GetBytes((ushort)Payload.Length), 0, 2);
            m.Write(Payload, 0, Payload.Length);
            byte[] body = m.ToArray();
            byte[] r = new byte[body.Length + 1];
            Array.Copy(body, r, body.Length);
            r[body.Length] = Checksum = ComputeChecksum(body, 0, body.Length, setting);
            ChecksumOk = true;
            return r;
        }

        // Quazal PRUDP v0 checksum; "setting" is the sum of the access key bytes.
        public static byte ComputeChecksum(byte[] data, int offset, int length, byte setting)
        {
            uint tmp = 0;
            for (int i = 0; i < length / 4; i++) tmp += BitConverter.ToUInt32(data, offset + i * 4);
            int left = length & 3;
            int pos = offset + length - left;
            int processed = 0;
            byte t2 = 0, t3 = 0, t4;
            if (left >= 2) { processed = 2; t2 = data[pos]; t3 = data[pos + 1]; pos += 2; }
            t4 = processed >= left ? setting : (byte)(setting + data[pos]);
            return (byte)((byte)(tmp >> 24) + (byte)(tmp >> 16) + (byte)(tmp >> 8) + (byte)tmp + t2 + t3 + t4);
        }

        public override string ToString()
        {
            StringBuilder f = new StringBuilder();
            if (Has(FLAG_ACK)) f.Append("ACK ");
            if (Has(FLAG_RELIABLE)) f.Append("REL ");
            if (Has(FLAG_NEED_ACK)) f.Append("NEED_ACK ");
            if (Has(FLAG_HAS_SIZE)) f.Append("SIZE ");
            return TypeNames[Type] + " [" + f.ToString().Trim() + "] " + Src.ToString("X2") + "->" + Dst.ToString("X2") +
                " sess=" + Session.ToString("X2") + " sig=" + Signature.ToString("X8") + " seq=" + Seq +
                (Type == SYN || Type == CONNECT ? " conn=" + ConnSig.ToString("X8") : "") +
                (Type == DATA ? " part=" + Part : "") + " len=" + Payload.Length + (ChecksumOk ? "" : " BAD-CHECKSUM");
        }
    }

    // ------------------------------------------------------------------ game ports

    // Public endpoint of each player's game socket (UDP 7777 locally), learned from the NAT echo
    // probes it sends to the server. NAT traversal probes are sent from and answered on that socket,
    // so it is the address other players must probe.
    // An echo carries no player id: it is matched to the player at the same IP that has no game port
    // yet, preferring the one that searched most recently (the tester starts right after a search).
    // Echoes seen before the player is known wait (30 s) to be claimed by the first connection from that IP.
    public static class GamePorts
    {
        class PendingEcho { public IPEndPoint EndPoint; public DateTime When; }
        static readonly Dictionary<string, PendingEcho> pending = new Dictionary<string, PendingEcho>();
        static readonly object sync = new object();

        public static void Seen(PrudpServer s, IPEndPoint ep)
        {
            lock (sync)
            {
                if (s.FindConnection(x => x.GameEndPoint != null && x.GameEndPoint.Equals(ep)) != null) return;
                List<Connection> same = s.FindConnections(x => x.Pid != 0 && x.EndPoint.Address.Equals(ep.Address));
                Connection best = null;
                foreach (Connection c in same)
                    if (c.GameEndPoint == null && (best == null || c.LastSearch > best.LastSearch)) best = c;
                if (best == null && same.Count == 1) best = same[0]; // NAT mapping of that player changed
                string ip = ep.Address.ToString();
                if (best != null)
                {
                    Assign(best, ep);
                    pending.Remove(ip);
                }
                else
                {
                    PendingEcho p = new PendingEcho();
                    p.EndPoint = new IPEndPoint(ep.Address, ep.Port);
                    p.When = DateTime.Now;
                    pending[ip] = p;
                }
            }
        }

        static void Assign(Connection c, IPEndPoint ep)
        {
            c.GameEndPoint = new IPEndPoint(ep.Address, ep.Port);
            Log.Write("NAT", "Game port of " + c + " is " + ep);
        }

        public static IPEndPoint Of(Connection c)
        {
            lock (sync)
            {
                if (c.GameEndPoint == null)
                {
                    PendingEcho p;
                    string ip = c.EndPoint.Address.ToString();
                    if (pending.TryGetValue(ip, out p) && (DateTime.Now - p.When).TotalSeconds < 30)
                    {
                        Assign(c, p.EndPoint);
                        pending.Remove(ip);
                    }
                }
                return c.GameEndPoint;
            }
        }
    }

    // ------------------------------------------------------------------ connection

    public enum Rc4Mode { Unknown, PerPacket, Stream }

    public class Connection
    {
        public IPEndPoint EndPoint;
        public uint ServerSig, ClientSig;
        public byte Session, ClientPort, ServerPort;
        public ushort NextSendSeq = 1;
        public readonly Dictionary<ushort, Pending> Unacked = new Dictionary<ushort, Pending>();
        public readonly HashSet<ushort> Received = new HashSet<ushort>();
        public MemoryStream Fragments;
        public Rc4Mode Rc4 = Rc4Mode.Unknown;
        public Rc4 RecvStream = new Rc4(Crypto.DataKey);
        public Rc4 SendStream = new Rc4(Crypto.DataKey);
        public bool ConnectPayloadEncrypted;
        public DateTime LastSeen = DateTime.Now;

        // user state
        public uint Pid;
        public string Username;
        public byte[] SessionKey;
        public uint ConnectionId;
        public List<string> StationUrls = new List<string>();
        public string PublicUrl;
        public uint ServerCallId;
        public IPEndPoint GameEndPoint;   // public endpoint of the player's game socket (from NAT echo)
        public DateTime LastSearch;       // last Turok search, used to match NAT echoes to players

        public class Pending
        {
            public byte[] Bytes;
            public DateTime LastSent;
            public int Tries;
        }

        public override string ToString()
        {
            return EndPoint + (Username != null ? " (" + Username + " pid=" + Pid + ")" : "");
        }
    }

    // ------------------------------------------------------------------ server

    public class PrudpServer
    {
        public readonly string Name;
        public readonly int Port;
        public readonly uint ServerPid;
        UdpClient udp;
        readonly Dictionary<string, Connection> conns = new Dictionary<string, Connection>();
        readonly object sync = new object();
        uint nextSig;
        readonly byte setting = Config.ChecksumSetting;

        // Called with the full RMC message (size header included).
        public Action<PrudpServer, Connection, byte[]> OnMessage;
        // Called for CONNECT packets carrying a payload; returns the reply payload.
        public Func<PrudpServer, Connection, byte[], byte[]> OnConnectPayload;
        // Called when a connection ends (DISCONNECT or 60 s without traffic).
        public Action<PrudpServer, Connection> OnDisconnect;
        const int IdleTimeoutSeconds = 60;

        public PrudpServer(string name, int port, uint serverPid, uint sigBase)
        {
            Name = name; Port = port; ServerPid = serverPid; nextSig = sigBase;
        }

        public void Start()
        {
            udp = new UdpClient(new IPEndPoint(IPAddress.Any, Port));
            // Windows only: do not let ICMP "port unreachable" break the receive loop.
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                const int SIO_UDP_CONNRESET = -1744830452;
                try { udp.Client.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null); }
                catch (Exception ex) { Log.Write(Name, "SIO_UDP_CONNRESET not available: " + ex.Message); }
            }
            Thread t = new Thread(ReceiveLoop); t.IsBackground = true; t.Start();
            Thread r = new Thread(ResendLoop); r.IsBackground = true; r.Start();
            Log.Write(Name, "Listening on UDP " + Port);
        }

        void ReceiveLoop()
        {
            while (true)
            {
                IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                byte[] data;
                try { data = udp.Receive(ref ep); }
                catch (Exception ex) { Log.Write(Name, "receive error: " + ex.Message); continue; }
                lock (sync)
                {
                    try { HandleDatagram(ep, data); }
                    catch (Exception ex) { Log.Write(Name, "!! error handling packet from " + ep + ": " + ex); }
                }
            }
        }

        void HandleDatagram(IPEndPoint ep, byte[] data)
        {
            if (data.Length > Config.MaxDatagramSize || data.Length < 10)
            {
                LogLimited("size:" + ep.Address, "ignored " + data.Length + "-byte datagram from " + ep);
                return;
            }
            if (data.Length >= 2 && data[0] == 0xEA && data[1] == 0xD0)
            {
                Log.Write(Name, "!! PRUDP v1 packet from " + ep + " (unsupported): " + Log.Hex(data));
                return;
            }
            int offset = 0;
            while (offset < data.Length)
            {
                PrudpPacket p = PrudpPacket.Parse(data, offset, setting);
                if ((p.Src >> 4) != PrudpPacket.StreamNATEcho)
                    Log.Packet(Name, "<< " + ep + " " + p);
                HandlePacket(ep, p);
                offset += p.Size;
            }
        }

        readonly Dictionary<string, int> echoCount = new Dictionary<string, int>();

        // NAT echo (stream 7, type 5): the game's connectivity tester sends these from its game port
        // and expects the same packet back (RVNATEcho / NATEchoStream.cpp just mirrors the payload).
        void HandleNatEcho(IPEndPoint ep, PrudpPacket p)
        {
            PrudpPacket r = new PrudpPacket();
            r.Src = p.Dst; r.Dst = p.Src;
            r.Type = p.Type; r.Flags = p.Flags;
            r.Session = p.Session; r.Signature = p.Signature; r.Seq = p.Seq;
            r.Payload = p.Payload;
            byte[] b = r.Build(setting);
            udp.Send(b, b.Length, ep);
            GamePorts.Seen(this, ep);
            string key = ep.ToString();
            int n;
            echoCount.TryGetValue(key, out n);
            if (echoCount.Count > 10000) echoCount.Clear();
            echoCount[key] = ++n;
            if (n <= 3 || n % 50 == 0)
                Log.Packet(Name, "   NAT echo #" + n + " answered to " + ep + ": " + Log.Hex(b));
        }

        // Logs a warning at most once a minute per key (abuse or misbehaving clients).
        readonly Dictionary<string, DateTime> lastWarn = new Dictionary<string, DateTime>();
        void LogLimited(string key, string message)
        {
            DateTime last;
            if (lastWarn.TryGetValue(key, out last) && (DateTime.Now - last).TotalSeconds < 60) return;
            if (lastWarn.Count > 10000) lastWarn.Clear();
            lastWarn[key] = DateTime.Now;
            Log.Write(Name, "!! " + message);
        }

        int ConnectionsFrom(IPAddress ip, string exceptKey)
        {
            int n = 0;
            foreach (KeyValuePair<string, Connection> kv in conns)
                if (kv.Key != exceptKey && kv.Value.EndPoint.Address.Equals(ip)) n++;
            return n;
        }

        void HandlePacket(IPEndPoint ep, PrudpPacket p)
        {
            if ((p.Src >> 4) == PrudpPacket.StreamNATEcho && p.Type == PrudpPacket.NATPING)
            {
                HandleNatEcho(ep, p);
                return;
            }
            string key = ep.ToString();
            Connection c;
            conns.TryGetValue(key, out c);
            if (c != null) c.LastSeen = DateTime.Now;

            switch (p.Type)
            {
                case PrudpPacket.SYN:
                    if (p.Has(PrudpPacket.FLAG_ACK)) return;
                    if (ConnectionsFrom(ep.Address, key) >= Config.MaxConnectionsPerIp)
                    {
                        LogLimited("conn:" + ep.Address, "too many connections from " + ep.Address + ", SYN ignored");
                        return;
                    }
                    if (c != null)
                    {
                        // Same endpoint reconnecting: close the old session properly first.
                        conns.Remove(key);
                        Log.Write(Name, "   reconnect from " + c + ", previous session closed");
                        if (OnDisconnect != null) OnDisconnect(this, c);
                    }
                    c = new Connection();
                    c.EndPoint = ep;
                    c.ServerSig = nextSig++;
                    c.Session = p.Session;
                    c.ClientPort = p.Src;
                    c.ServerPort = p.Dst;
                    conns[key] = c;
                    {
                        PrudpPacket r = Reply(c, p, PrudpPacket.SYN, PrudpPacket.FLAG_ACK);
                        r.Signature = p.Signature;
                        r.ConnSig = c.ServerSig;
                        SendRaw(c, r);
                    }
                    return;

                case PrudpPacket.CONNECT:
                    if (c == null || p.Has(PrudpPacket.FLAG_ACK)) return;
                    c.ClientSig = p.ConnSig;
                    c.Session = p.Session;
                    {
                        PrudpPacket r = Reply(c, p, PrudpPacket.CONNECT, PrudpPacket.FLAG_ACK);
                        r.Signature = c.ClientSig;
                        r.ConnSig = c.ServerSig;
                        if (p.Payload.Length > 0)
                        {
                            Log.Packet(Name, "   CONNECT payload: " + Log.Hex(p.Payload));
                            byte[] reply = HandleConnectPayload(c, p.Payload);
                            if (reply != null)
                                r.Payload = c.ConnectPayloadEncrypted ? EncodeUnreliablePayload(reply) : reply;
                        }
                        SendRaw(c, r);
                        c.Received.Add(p.Seq);
                    }
                    return;

                case PrudpPacket.DATA:
                    if (c == null) { Log.Write(Name, "   DATA from unknown connection, ignored"); return; }
                    if (p.Has(PrudpPacket.FLAG_ACK))
                    {
                        if (c.Unacked.Remove(p.Seq)) Log.Packet(Name, "   ack for our seq " + p.Seq);
                        return;
                    }
                    if (p.Has(PrudpPacket.FLAG_NEED_ACK))
                    {
                        PrudpPacket a = Reply(c, p, PrudpPacket.DATA, PrudpPacket.FLAG_ACK);
                        a.Signature = c.ClientSig;
                        a.Part = p.Part;
                        SendRaw(c, a);
                    }
                    if (p.Has(PrudpPacket.FLAG_RELIABLE))
                    {
                        if (c.Received.Contains(p.Seq)) { Log.Packet(Name, "   duplicate seq " + p.Seq + ", ignored"); return; }
                        c.Received.Add(p.Seq);
                    }
                    HandleData(c, p);
                    return;

                case PrudpPacket.PING:
                    if (c == null || p.Has(PrudpPacket.FLAG_ACK)) return;
                    {
                        PrudpPacket r = Reply(c, p, PrudpPacket.PING, PrudpPacket.FLAG_ACK);
                        r.Signature = c.ClientSig;
                        SendRaw(c, r);
                    }
                    return;

                case PrudpPacket.DISCONNECT:
                    if (c == null) return;
                    {
                        PrudpPacket r = Reply(c, p, PrudpPacket.DISCONNECT, PrudpPacket.FLAG_ACK);
                        r.Signature = c.ClientSig;
                        SendRaw(c, r);
                    }
                    conns.Remove(key);
                    Log.Write(Name, "   connection closed: " + c);
                    if (OnDisconnect != null) OnDisconnect(this, c);
                    return;

                default:
                    Log.Write(Name, "   unhandled packet type, payload: " + Log.Hex(p.Payload));
                    return;
            }
        }

        byte[] HandleConnectPayload(Connection c, byte[] raw)
        {
            if (OnConnectPayload == null) return null;
            if (LooksLikeTwoBuffers(raw))
            {
                c.ConnectPayloadEncrypted = false;
                return OnConnectPayload(this, c, raw);
            }
            byte[] dec = Rc4.Once(Crypto.DataKey, raw);
            if (dec.Length > 1 && dec[0] == 0)
            {
                byte[] inner = new byte[dec.Length - 1];
                Array.Copy(dec, 1, inner, 0, inner.Length);
                if (LooksLikeTwoBuffers(inner))
                {
                    c.ConnectPayloadEncrypted = true;
                    Log.Packet(Name, "   CONNECT payload was RC4/CD&ML encoded");
                    return OnConnectPayload(this, c, inner);
                }
            }
            Log.Write(Name, "!! CONNECT payload format not recognised");
            return OnConnectPayload(this, c, raw);
        }

        static bool LooksLikeTwoBuffers(byte[] b)
        {
            try
            {
                QReader r = new QReader(b);
                r.Buffer(); r.Buffer();
                return r.Remaining == 0;
            }
            catch { return false; }
        }

        byte[] EncodeUnreliablePayload(byte[] plain)
        {
            byte[] withFlag = new byte[plain.Length + 1];
            Array.Copy(plain, 0, withFlag, 1, plain.Length);
            return Rc4.Once(Crypto.DataKey, withFlag);
        }

        // ---------------------------------------------------------- DATA payloads

        void HandleData(Connection c, PrudpPacket p)
        {
            if (p.Payload.Length == 0) return;
            byte[] perPacket = Rc4.Once(Crypto.DataKey, p.Payload);
            byte[] stream = c.RecvStream.Process(p.Payload);
            bool fragmentStart = c.Fragments == null || c.Fragments.Length == 0;
            bool firstPartOnly = fragmentStart && p.Part == 0;

            byte[] chosen;
            if (c.Rc4 == Rc4Mode.Stream) chosen = stream;
            else if (c.Rc4 == Rc4Mode.PerPacket) chosen = perPacket;
            else
            {
                bool okPer = Plausible(perPacket, firstPartOnly);
                bool okStream = Plausible(stream, firstPartOnly);
                if (okPer && !okStream) { c.Rc4 = Rc4Mode.PerPacket; Log.Packet(Name, "   RC4 mode detected: reset per packet"); }
                else if (okStream && !okPer) { c.Rc4 = Rc4Mode.Stream; Log.Packet(Name, "   RC4 mode detected: continuous stream"); }
                chosen = c.Rc4 == Rc4Mode.Stream ? stream : perPacket;
            }

            byte[] body;
            if (chosen[0] == 0)
            {
                body = new byte[chosen.Length - 1];
                Array.Copy(chosen, 1, body, 0, body.Length);
            }
            else
            {
                body = Decompress(chosen);
                if (body == null)
                {
                    Log.Write(Name, "!! cannot decompress payload: " + Log.Hex(chosen));
                    return;
                }
            }

            if (c.Fragments == null) c.Fragments = new MemoryStream();
            c.Fragments.Write(body, 0, body.Length);
            if (p.Part != 0) return; // more fragments follow
            byte[] message = c.Fragments.ToArray();
            c.Fragments = null;
            if (OnMessage != null) OnMessage(this, c, message);
        }

        static bool Plausible(byte[] dec, bool completeMessage)
        {
            if (dec.Length < 1) return false;
            if (dec[0] == 0)
            {
                if (!completeMessage) return true;
                return dec.Length >= 5 && BitConverter.ToUInt32(dec, 1) == (uint)(dec.Length - 5);
            }
            byte[] b = Decompress(dec);
            if (b == null) return false;
            return !completeMessage || (b.Length >= 4 && BitConverter.ToUInt32(b, 0) == (uint)(b.Length - 4));
        }

        // Payload with a non-zero first byte is compressed: Turok uses LZO1X, zlib kept as fallback.
        static byte[] Decompress(byte[] withFlag)
        {
            try { return Lzo.Decompress(withFlag, 1, withFlag.Length - 1); }
            catch { }
            try
            {
                byte[] z = new byte[withFlag.Length - 1];
                Array.Copy(withFlag, 1, z, 0, z.Length);
                return Crypto.Inflate(z);
            }
            catch { return null; }
        }

        // ---------------------------------------------------------- sending

        const int MaxFragment = 900;

        public Connection FindConnection(Predicate<Connection> match)
        {
            lock (sync)
            {
                foreach (Connection c in conns.Values)
                    if (match(c)) return c;
                return null;
            }
        }

        public List<Connection> FindConnections(Predicate<Connection> match)
        {
            lock (sync)
            {
                List<Connection> l = new List<Connection>();
                foreach (Connection c in conns.Values)
                    if (match(c)) l.Add(c);
                return l;
            }
        }

        public void SendMessage(Connection c, byte[] message)
        {
            lock (sync)
            {
                int count = Math.Max(1, (message.Length + MaxFragment - 1) / MaxFragment);
                for (int i = 0; i < count; i++)
                {
                    int off = i * MaxFragment;
                    int len = Math.Min(MaxFragment, message.Length - off);
                    byte[] plain = new byte[len + 1]; // first byte 0 = not compressed
                    Array.Copy(message, off, plain, 1, len);
                    byte[] stream = c.SendStream.Process(plain);
                    byte[] enc = c.Rc4 == Rc4Mode.Stream ? stream : Rc4.Once(Crypto.DataKey, plain);

                    PrudpPacket p = new PrudpPacket();
                    p.Src = c.ServerPort; p.Dst = c.ClientPort;
                    p.Type = PrudpPacket.DATA;
                    p.Flags = PrudpPacket.FLAG_RELIABLE | PrudpPacket.FLAG_NEED_ACK;
                    p.Session = c.Session;
                    p.Signature = c.ClientSig;
                    p.Seq = c.NextSendSeq++;
                    p.Part = (byte)(i == count - 1 ? 0 : i + 1);
                    p.Payload = enc;
                    byte[] bytes = SendRaw(c, p);
                    Connection.Pending pend = new Connection.Pending();
                    pend.Bytes = bytes; pend.LastSent = DateTime.Now; pend.Tries = 1;
                    c.Unacked[p.Seq] = pend;
                }
            }
        }

        PrudpPacket Reply(Connection c, PrudpPacket p, int type, int flags)
        {
            PrudpPacket r = new PrudpPacket();
            r.Src = p.Dst; r.Dst = p.Src;
            r.Type = type; r.Flags = flags;
            r.Session = c.Session;
            r.Seq = p.Seq;
            return r;
        }

        byte[] SendRaw(Connection c, PrudpPacket p)
        {
            byte[] b = p.Build(setting);
            udp.Send(b, b.Length, c.EndPoint);
            Log.Packet(Name, ">> " + c.EndPoint + " " + p);
            return b;
        }

        void ResendLoop()
        {
            while (true)
            {
                Thread.Sleep(250);
                lock (sync)
                {
                    foreach (Connection c in new List<Connection>(conns.Values))
                    {
                        if ((DateTime.Now - c.LastSeen).TotalSeconds > IdleTimeoutSeconds)
                        {
                            conns.Remove(c.EndPoint.ToString());
                            Log.Write(Name, "   connection timed out: " + c);
                            if (OnDisconnect != null) OnDisconnect(this, c);
                            continue;
                        }
                        foreach (ushort seq in new List<ushort>(c.Unacked.Keys))
                        {
                            Connection.Pending pend = c.Unacked[seq];
                            if ((DateTime.Now - pend.LastSent).TotalMilliseconds < 1000) continue;
                            if (pend.Tries >= 8)
                            {
                                Log.Write(Name, "!! giving up on seq " + seq + " to " + c);
                                c.Unacked.Remove(seq);
                                continue;
                            }
                            pend.Tries++;
                            pend.LastSent = DateTime.Now;
                            udp.Send(pend.Bytes, pend.Bytes.Length, c.EndPoint);
                            Log.Packet(Name, ">> resend seq " + seq + " to " + c + " (try " + pend.Tries + ")");
                        }
                    }
                }
            }
        }
    }
}
