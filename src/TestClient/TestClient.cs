// End-to-end test that behaves like the Turok client seen in the captures:
// GUEST login on the auth server, ticket decryption, secure CONNECT, Register,
// and one unimplemented call. Build with build.bat, run while TurokServer is running.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using TurokServer;

static class TestClient
{
    static readonly byte Setting = Config.ChecksumSetting;
    static int failures;

    static int Main()
    {
        try { Run(); }
        catch (Exception ex) { Console.WriteLine("EXCEPTION: " + ex); failures++; }
        Console.WriteLine(failures == 0 ? "\nALL CHECKS PASSED" : "\n" + failures + " CHECK(S) FAILED");
        return failures == 0 ? 0 : 1;
    }

    static void Check(bool ok, string what)
    {
        Console.WriteLine((ok ? "  [OK]   " : "  [FAIL] ") + what);
        if (!ok) failures++;
    }

    class Session
    {
        public UdpClient Udp;
        public IPEndPoint Server;
        public uint ServerSig;
        public uint MySig = 0x768CBB79;
        public ushort Seq = 1;
        public byte Sess = 0xA6;
    }

    static void Run()
    {
        Console.WriteLine("== NAT echo (packet captured from the game)");
        byte[] echo = { 0x71, 0x71, 0x05, 0x00, 0, 0, 0, 0, 0, 0, 0x44, 0x02, 0x2D };
        PrudpPacket ep = PrudpPacket.Parse(echo, 0, Setting);
        Check(ep.ChecksumOk, "captured NAT echo has a valid checksum with setting 0");
        // Sent before the host logs in: the server keeps it and gives it to the first player from 127.0.0.1.
        int hostGamePort;
        using (UdpClient u = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
        {
            u.Client.ReceiveTimeout = 3000;
            hostGamePort = ((IPEndPoint)u.Client.LocalEndPoint).Port;
            u.Send(echo, echo.Length, new IPEndPoint(IPAddress.Loopback, Config.SecurePort));
            IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
            byte[] back = u.Receive(ref from);
            Check(Log.Hex(back) == Log.Hex(echo), "secure server mirrors the NAT echo: " + Log.Hex(back));
        }

        Console.WriteLine("== Authentication server");
        Session a = Open(Config.AuthPort, null);
        byte[] login = Request(Protocols.Authentication, 4, 1, new QWriter().String("GUEST").ToArray());
        byte[] resp = Call(a, login);
        QReader r = new QReader(resp);
        r.U32(); byte proto = r.U8(); bool success = r.U8() == 1; uint callId = r.U32(); uint method = r.U32();
        Check(proto == Protocols.Authentication && success && callId == 4 && method == (1 | 0x8000), "login response header");
        uint result = r.U32(); uint pid = r.U32(); byte[] ticket = r.Buffer(); string url = r.String();
        Check(result == QResult.Success && pid == Config.GuestPid, "login result success, pid " + pid);
        Console.WriteLine("  secure url: " + url);

        byte[] plain = Kerberos.Open(Crypto.DeriveKey(pid, Config.GuestPassword), ticket);
        Check(plain != null, "ticket HMAC valid with key derived from the guest password");
        QReader tr = new QReader(plain);
        byte[] sessionKey = tr.Bytes(16); uint target = tr.U32(); byte[] inner = tr.Buffer();
        Check(target == Config.SecureServerPid, "ticket target is the secure server");

        Console.WriteLine("== Secure server");
        uint check = 0x11223344;
        byte[] reqData = Kerberos.Seal(sessionKey, new QWriter().U32(pid).U32(1).U32(check).ToArray());
        byte[] connectPayload = new QWriter().Buffer(inner).Buffer(reqData).ToArray();
        Session s = Open(Config.SecurePort, connectPayload);

        byte[] reg = Request(Protocols.Secure, 5, 1, new QWriter().U32(1).String("prudp:/address=192.168.1.2;port=9989;sid=15;type=2").ToArray());
        resp = Call(s, reg);
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        result = r.U32(); uint cid = r.U32(); string pub = r.String();
        Check(success && result == QResult.Success, "Register success, cid " + cid + ", public url " + pub);

        byte[] unknown = Request(Protocols.MatchMaking, 6, 1, new byte[0]);
        resp = Call(s, unknown);
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; uint err = r.U32();
        Check(!success && err == QResult.Core_NotImplemented, "unimplemented call returns Core::NotImplemented");

        Console.WriteLine("== Account creation");
        Check(Crypto.ToHex(Crypto.UserKey(1234, Crypto.BaseKey("sample"))) == Crypto.ToHex(Md5Chain("sample", 65000 + 1234 % 1024)),
              "two-step key derivation equals MD5 applied 65000 + pid % 1024 times");
        string user = "Test" + Environment.TickCount;
        string keyHex = Crypto.ToHex(Crypto.BaseKey("secret"));
        byte[] create = Request(Protocols.AccountManagement, 7, 1,
            new QWriter().String(user).String(keyHex).U32(0x20).String("secret").ToArray());
        resp = Call(s, create);
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        Check(success && r.U32() == QResult.Success, "CreateAccount " + user);
        resp = Call(s, Request(Protocols.AccountManagement, 8, 1,
            new QWriter().String(user).String(keyHex).U32(0x20).String("secret").ToArray()));
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; err = r.U32();
        Check(!success && err == QResult.RendezVous_UsernameAlreadyExists, "duplicate CreateAccount refused");

        Console.WriteLine("== Turok protocol (LZO payload captured from the game)");
        string lzoHex = "01 00 0D 5A 00 00 00 E4 0F 00 00 00 01 00 00 00 0F 00 54 75 72 6F 6B 47 61 74 68 65 72 69 6E 67 00 35 42 03 31 00 2C 00 00 02 02 00 08 00 64 2C 48 00 70 07 68 02 6C 08 0A 00 00 02 02 00 01 01 00 00 00 01 00 00 11 00 00";
        string[] parts = lzoHex.Split(' ');
        byte[] lzoPayload = new byte[parts.Length];
        for (int i = 0; i < parts.Length; i++) lzoPayload[i] = Convert.ToByte(parts[i], 16);
        resp = CallPayload(s, lzoPayload);
        r = new QReader(resp);
        r.U32(); proto = r.U8(); success = r.U8() == 1; callId = r.U32(); method = r.U32();
        uint gid = r.U32();
        Check(proto == 0x64 && success && callId == 15 && method == (1 | 0x8000), "RegisterGathering answered, gathering id 0x" + gid.ToString("X"));

        Session a2 = Open(Config.AuthPort, null);
        resp = Call(a2, Request(Protocols.Authentication, 9, 1, new QWriter().String(user).ToArray()));
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        result = r.U32(); pid = r.U32(); ticket = r.Buffer();
        Check(success && result == QResult.Success && pid != Config.GuestPid, "login as new user, pid " + pid);
        byte[] plain2 = Kerberos.Open(Crypto.DeriveKey(pid, "secret"), ticket);
        Check(plain2 != null, "ticket opens with the new user's password");

        Console.WriteLine("== Second player (other public IP, 127.0.0.2) searches the first player's gathering");
        QReader tr2 = new QReader(plain2);
        byte[] key2 = tr2.Bytes(16); tr2.U32(); byte[] inner2 = tr2.Buffer();
        byte[] req2 = Kerberos.Seal(key2, new QWriter().U32(pid).U32(1).U32(0x11223344).ToArray());
        IPAddress otherIp = IPAddress.Parse("127.0.0.2");
        Session s2 = Open(Config.SecurePort, new QWriter().Buffer(inner2).Buffer(req2).ToArray(), otherIp);
        Call(s2, Request(Protocols.Secure, 20, 1, new QWriter().U32(1).String("prudp:/address=192.168.1.3;port=9103;sid=15").ToArray()));
        int joinerGamePort = SendNatEcho(otherIp);
        byte[] search = new QWriter().U8(10).U32(100).U32(1).U8(1).U8(2).U8(0xFF).ToArray();
        resp = Call(s2, Request(TurokProtocol.Id, 10, 6, search));
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        uint count = success ? r.U32() : 0;
        Check(success && count == 1, "search category 2 returns 1 gathering");
        if (count == 1)
        {
            string cls = r.String(); r.U32(); int len = (int)r.U32();
            Gathering g = Gathering.Read(r, len);
            Check(cls == "TurokGathering" && g.Id == gid && g.Category == 2 && g.Owner == Config.GuestPid, "result is the first player's gathering: " + g);
            Check(g.OpenSlots == g.MaxParticipants - 1, "open slots filled in by the server (" + g.OpenSlots + ")");
            uint names = r.U32(); string host = names == 1 ? r.String() : null;
            Check(names == 1 && host == "GUEST", "second list holds the host name \"" + host + "\"");
            uint urlSets = r.U32(); uint urlGid = r.U32(); List<string> urls = r.StringList();
            Check(urlSets == 1 && urlGid == gid && urls.Count >= 1 && r.Remaining == 0,
                  "third list holds the host URLs: " + string.Join(" | ", urls.ToArray()));
            Check(urls.Count >= 1 && urls[0].Contains("RVCID=") && urls[0].Contains("PID=100") &&
                  urls[0].Contains("address=127.0.0.1;port=" + hostGamePort + ";"),
                  "first host URL is the host's public game port (from NAT echo) with PID and RVCID");
        }
        resp = Call(s2, Request(TurokProtocol.Id, 14, 6, new QWriter().U8(10).U32(100).U32(1).U8(1).U8(2).U8(0).ToArray()));
        Check(!IsEmptySearch(resp), "CUSTOM MATCH search (size small) finds the small gathering");
        resp = Call(s2, Request(TurokProtocol.Id, 15, 6, new QWriter().U8(10).U32(100).U32(1).U8(1).U8(2).U8(1).ToArray()));
        Check(IsEmptySearch(resp), "CUSTOM MATCH search (size large) does not find it");
        resp = Call(s2, Request(TurokProtocol.Id, 11, 6, new QWriter().U8(10).U32(100).U32(1).U8(1).U8(3).U8(0xFF).ToArray()));
        Check(IsEmptySearch(resp), "search in another category returns three empty lists");

        Console.WriteLine("== MatchMaking SetState (method 30)");
        resp = Call(s, Request(Protocols.MatchMaking, 40, 30, new QWriter().U32(gid).U32(2).ToArray()));
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        Check(success && r.Remaining == 1 && r.U8() == 1, "SetState returns true");

        Console.WriteLine("== Join and leave (methods 5 and 2)");
        resp = Call(s2, Request(TurokProtocol.Id, 30, 5, new QWriter().U32(gid).U8(0).ToArray()));
        Check(IsVoidSuccess(resp), "join (method 5) returns an empty success");
        Check(SearchOpenSlots(s2, 31) == 6, "after the join the host's match shows 6 open slots");
        resp = Call(s2, Request(TurokProtocol.Id, 32, 2, new QWriter().U32(gid).U8(0).ToArray()));
        Check(IsVoidSuccess(resp), "leave (method 2 on the host's gathering) returns an empty success");
        Check(SearchOpenSlots(s2, 33) == 7, "after leaving the match shows 7 open slots again");

        Console.WriteLine("== NAT traversal: joining player asks the server to warn the host");
        byte[] natReq = new QWriter().U32(1).String("udp:/address=127.0.0.1;port=9103;RVCID=1").String("").ToArray();
        resp = Call(s2, Request(Protocols.NATTraversal, 16, 3, natReq));
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        Check(success && r.Remaining == 0, "RequestProbeInitiationExt answered with an empty success");
        byte[] call = ReceiveMessage(s);
        r = new QReader(call);
        r.U32(); byte cproto = r.U8(); r.U32(); uint cmethod = r.U32(); string probeUrl = r.String();
        Check(cproto == (Protocols.NATTraversal | 0x80) && cmethod == 2 && probeUrl.StartsWith("udp:/") && probeUrl.Contains("RVCID=2") &&
              probeUrl.Contains("address=127.0.0.2;port=" + joinerGamePort + ";"),
              "host receives InitiateProbe(" + probeUrl + ") with the joiner's own game port");

        Console.WriteLine("== Third player behind the host's public IP gets the host's LAN address");
        string user3 = "Lan" + Environment.TickCount;
        resp = Call(s, Request(Protocols.AccountManagement, 50, 1,
            new QWriter().String(user3).String(Crypto.ToHex(Crypto.BaseKey("pw3"))).U32(0x20).String("pw3").ToArray()));
        uint pid3;
        Session s3 = LoginSecure(user3, "pw3", IPAddress.Loopback, "prudp:/address=192.168.1.7;port=9103;sid=15", out pid3);
        resp = Call(s3, Request(TurokProtocol.Id, 51, 6, search));
        List<string> lanUrls = FirstResultUrls(resp);
        Check(lanUrls != null && lanUrls[0].Contains("address=192.168.1.2;port=" + Config.GamePort + ";"),
              "first host URL is the host's LAN address and game port: " + (lanUrls != null ? lanUrls[0] : "none"));

        PrudpPacket bye = New(PrudpPacket.DISCONNECT, PrudpPacket.FLAG_RELIABLE | PrudpPacket.FLAG_NEED_ACK, s.ServerSig, s.Seq++);
        Send(s, bye);
        Receive(s);
        resp = Call(s2, Request(TurokProtocol.Id, 12, 6, search));
        Check(IsEmptySearch(resp), "gathering removed after the first player disconnects");

        resp = Call(s2, Request(TurokProtocol.Id, 13, 2, new QWriter().U32(0x1234).U8(0).ToArray()));
        r = new QReader(resp);
        r.U32(); r.U8(); success = r.U8() == 1; r.U32(); r.U32();
        Check(success && r.Remaining == 0, "unregister (method 2) returns an empty success");
    }

    static bool IsVoidSuccess(byte[] resp)
    {
        QReader r = new QReader(resp);
        r.U32(); r.U8();
        bool ok = r.U8() == 1;
        r.U32(); r.U32();
        return ok && r.Remaining == 0;
    }

    // Searches category 2 (any size) and returns the open slots of the first result, or -1.
    static int SearchOpenSlots(Session s, uint callId)
    {
        byte[] resp = Call(s, Request(TurokProtocol.Id, callId, 6, new QWriter().U8(10).U32(100).U32(1).U8(1).U8(2).U8(0xFF).ToArray()));
        QReader r = new QReader(resp);
        r.U32(); r.U8();
        if (r.U8() != 1) return -1;
        r.U32(); r.U32();
        if (r.U32() == 0) return -1;
        r.String(); r.U32(); int len = (int)r.U32();
        return Gathering.Read(r, len).OpenSlots;
    }

    static bool IsEmptySearch(byte[] resp)
    {
        QReader r = new QReader(resp);
        r.U32(); r.U8();
        if (r.U8() != 1) return false;
        r.U32(); r.U32();
        return r.U32() == 0 && r.U32() == 0 && r.U32() == 0 && r.Remaining == 0;
    }

    // Sends a NAT echo from a new socket bound to the given IP and returns its port.
    static int SendNatEcho(IPAddress bind)
    {
        byte[] echo = { 0x71, 0x71, 0x05, 0x00, 0, 0, 0, 0, 0, 0, 0x44, 0x02, 0x2D };
        using (UdpClient u = new UdpClient(new IPEndPoint(bind, 0)))
        {
            u.Client.ReceiveTimeout = 3000;
            u.Send(echo, echo.Length, new IPEndPoint(IPAddress.Loopback, Config.SecurePort));
            IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
            u.Receive(ref from);
            return ((IPEndPoint)u.Client.LocalEndPoint).Port;
        }
    }

    // Auth login + secure CONNECT with the ticket + Register; returns the secure session.
    static Session LoginSecure(string user, string password, IPAddress bind, string registerUrl, out uint pid)
    {
        Session a = Open(Config.AuthPort, null, bind);
        byte[] resp = Call(a, Request(Protocols.Authentication, 60, 1, new QWriter().String(user).ToArray()));
        QReader r = new QReader(resp);
        r.U32(); r.U8(); r.U8(); r.U32(); r.U32();
        r.U32(); pid = r.U32(); byte[] ticket = r.Buffer();
        QReader t = new QReader(Kerberos.Open(Crypto.DeriveKey(pid, password), ticket));
        byte[] key = t.Bytes(16); t.U32(); byte[] inner = t.Buffer();
        byte[] req = Kerberos.Seal(key, new QWriter().U32(pid).U32(1).U32(0x11223344).ToArray());
        Session s = Open(Config.SecurePort, new QWriter().Buffer(inner).Buffer(req).ToArray(), bind);
        Call(s, Request(Protocols.Secure, 61, 1, new QWriter().U32(1).String(registerUrl).ToArray()));
        return s;
    }

    static List<string> FirstResultUrls(byte[] resp)
    {
        QReader r = new QReader(resp);
        r.U32(); r.U8();
        if (r.U8() != 1) return null;
        r.U32(); r.U32();
        uint n = r.U32();
        if (n == 0) return null;
        for (uint i = 0; i < n; i++) { r.String(); r.U32(); r.Bytes((int)r.U32()); }
        n = r.U32();
        for (uint i = 0; i < n; i++) r.String();
        r.U32(); r.U32();
        return r.StringList();
    }

    static Session Open(int port, byte[] connectPayload)
    {
        return Open(port, connectPayload, IPAddress.Loopback);
    }

    static Session Open(int port, byte[] connectPayload, IPAddress bind)
    {
        Session s = new Session();
        s.Udp = new UdpClient(new IPEndPoint(bind, 0));
        s.Udp.Client.ReceiveTimeout = 3000;
        s.Server = new IPEndPoint(IPAddress.Loopback, port);

        PrudpPacket syn = New(PrudpPacket.SYN, PrudpPacket.FLAG_NEED_ACK, 0, 0);
        syn.Session = 0;
        Send(s, syn);
        PrudpPacket synAck = Receive(s);
        Check(synAck.Type == PrudpPacket.SYN && synAck.Has(PrudpPacket.FLAG_ACK) && synAck.ChecksumOk, "SYN-ACK received, checksum ok");
        s.ServerSig = synAck.ConnSig;

        PrudpPacket con = New(PrudpPacket.CONNECT, PrudpPacket.FLAG_RELIABLE | PrudpPacket.FLAG_NEED_ACK, s.ServerSig, s.Seq++);
        con.ConnSig = s.MySig;
        if (connectPayload != null) con.Payload = connectPayload;
        Send(s, con);
        PrudpPacket conAck = Receive(s);
        Check(conAck.Type == PrudpPacket.CONNECT && conAck.Signature == s.MySig, "CONNECT-ACK received");
        if (connectPayload != null)
        {
            QReader r = new QReader(conAck.Payload);
            byte[] inner = r.Buffer();
            Check(inner.Length == 4 && BitConverter.ToUInt32(inner, 0) == 0x11223345, "CONNECT-ACK carries check + 1");
        }
        return s;
    }

    static byte[] Request(int protocol, uint callId, uint method, byte[] parameters)
    {
        byte[] body = new QWriter().U8((byte)(protocol | 0x80)).U32(callId).U32(method).Bytes(parameters).ToArray();
        return new QWriter().U32((uint)body.Length).Bytes(body).ToArray();
    }

    static byte[] Call(Session s, byte[] message)
    {
        byte[] plain = new byte[message.Length + 1];
        Array.Copy(message, 0, plain, 1, message.Length);
        return CallPayload(s, plain);
    }

    // plain = compression flag byte + (compressed) RMC message, before RC4.
    static byte[] CallPayload(Session s, byte[] plain)
    {
        PrudpPacket d = New(PrudpPacket.DATA, PrudpPacket.FLAG_RELIABLE | PrudpPacket.FLAG_NEED_ACK, s.ServerSig, s.Seq++);
        d.Payload = Rc4.Once(Crypto.DataKey, plain);
        Send(s, d);
        while (true)
        {
            PrudpPacket p = Receive(s);
            if (p.Type != PrudpPacket.DATA) continue;
            if (p.Has(PrudpPacket.FLAG_ACK)) { Check(p.Seq == d.Seq, "server ACKed our seq " + d.Seq); continue; }
            PrudpPacket ack = New(PrudpPacket.DATA, PrudpPacket.FLAG_ACK, s.ServerSig, p.Seq);
            Send(s, ack);
            Check(p.ChecksumOk && p.Part == 0, "response packet seq " + p.Seq + " checksum ok");
            byte[] dec = Rc4.Once(Crypto.DataKey, p.Payload);
            Check(dec[0] == 0, "response not compressed");
            byte[] msg = new byte[dec.Length - 1];
            Array.Copy(dec, 1, msg, 0, msg.Length);
            return msg;
        }
    }

    // Waits for a server-initiated DATA message, ACKs it and returns the RMC message.
    static byte[] ReceiveMessage(Session s)
    {
        while (true)
        {
            PrudpPacket p = Receive(s);
            if (p.Type != PrudpPacket.DATA || p.Has(PrudpPacket.FLAG_ACK)) continue;
            Send(s, New(PrudpPacket.DATA, PrudpPacket.FLAG_ACK, s.ServerSig, p.Seq));
            byte[] dec = Rc4.Once(Crypto.DataKey, p.Payload);
            byte[] msg = new byte[dec.Length - 1];
            Array.Copy(dec, 1, msg, 0, msg.Length);
            return msg;
        }
    }

    static byte[] Md5Chain(string password, int count)
    {
        using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
        {
            byte[] b = System.Text.Encoding.ASCII.GetBytes(password);
            for (int i = 0; i < count; i++) b = md5.ComputeHash(b);
            return b;
        }
    }

    static PrudpPacket New(int type, int flags, uint sig, ushort seq)
    {
        PrudpPacket p = new PrudpPacket();
        p.Src = 0x3F; p.Dst = 0x31; p.Type = type; p.Flags = flags; p.Signature = sig; p.Seq = seq; p.Session = 0xA6;
        return p;
    }

    static void Send(Session s, PrudpPacket p)
    {
        byte[] b = p.Build(Setting);
        s.Udp.Send(b, b.Length, s.Server);
    }

    static PrudpPacket Receive(Session s)
    {
        IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
        byte[] b = s.Udp.Receive(ref ep);
        return PrudpPacket.Parse(b, 0, Setting);
    }
}
