using System;
using System.Collections.Generic;
using System.Net;

namespace TurokServer
{
    // Ticket granting service on the authentication server (protocol 0x0A).
    public static class AuthenticationService
    {
        const uint Login = 1, LoginEx = 2, RequestTicket = 3;

        public static bool Handle(PrudpServer s, Connection c, RmcRequest q)
        {
            QReader r = new QReader(q.Params);
            switch (q.MethodId)
            {
                case Login:
                    {
                        string user = r.String();
                        DoLogin(s, c, q, user);
                        return true;
                    }
                case LoginEx:
                    {
                        string user = r.String();
                        Log.Write("AUTH", "LoginEx extra data: " + Log.Hex(r.Rest()));
                        DoLogin(s, c, q, user);
                        return true;
                    }
                case RequestTicket:
                    {
                        uint source = r.U32();
                        uint target = r.U32();
                        Account a = Accounts.Find(source);
                        if (a == null) { Rmc.Error(s, c, q, QResult.RendezVous_InvalidUsername); return true; }
                        byte[] ticket = Kerberos.BuildClientTicket(a, target, Kerberos.NewSessionKey());
                        Log.Write("AUTH", "RequestTicket for pid " + source + " -> target " + target);
                        Rmc.Respond(s, c, q, new QWriter().U32(QResult.Success).Buffer(ticket).ToArray());
                        return true;
                    }
            }
            return false;
        }

        static void DoLogin(PrudpServer s, Connection c, RmcRequest q, string user)
        {
            Account a = Accounts.Find(user);
            if (a == null)
            {
                Log.Write("AUTH", "Login refused, unknown user \"" + user + "\"");
                Rmc.Error(s, c, q, QResult.RendezVous_InvalidUsername);
                return;
            }
            c.Pid = a.Pid; c.Username = a.Username;

            byte[] ticket = Kerberos.BuildClientTicket(a, Config.SecureServerPid, Kerberos.NewSessionKey());
            string secureUrl = "prudps:/address=" + Config.PublicAddress + ";port=" + Config.SecurePort +
                               ";CID=1;PID=" + Config.SecureServerPid + ";sid=1;stream=3;type=2";

            QWriter w = new QWriter();
            w.U32(QResult.Success);
            w.U32(a.Pid);
            w.Buffer(ticket);
            // RVConnectionData
            w.String(secureUrl);
            w.U32(0);          // special protocols list (empty)
            w.String("");      // special protocols URL
            w.String("Turok 2008 emulator"); // return message
            Log.Write("AUTH", "Login OK for \"" + a.Username + "\" pid=" + a.Pid + ", secure server " + secureUrl);
            Rmc.Respond(s, c, q, w.ToArray());
        }
    }

    // Account management (protocol 0x19), used by the profile screen to create Quazal accounts.
    public static class AccountManagementService
    {
        const uint CreateAccount = 1, ChangePassword = 4, GetName = 6, CreateAccountWithCustomData = 21;

        public static bool Handle(PrudpServer s, Connection c, RmcRequest q)
        {
            QReader r = new QReader(q.Params);
            switch (q.MethodId)
            {
                case CreateAccount:
                case CreateAccountWithCustomData:
                    {
                        string name = r.String();
                        string key = r.String();
                        uint groups = r.Remaining >= 4 ? r.U32() : 0;
                        // Turok fills the fourth field (email in other games) with the plain password: never log or store it.
                        if (r.Remaining >= 2) r.String();
                        if (r.Remaining > 0) Log.Write("ACCOUNT", "CreateAccount extra data: " + Log.Hex(r.Rest()));
                        Log.Write("ACCOUNT", "CreateAccount name=\"" + name + "\" groups=0x" + groups.ToString("X"));
                        if (name.Length == 0 || !Crypto.IsKeyHex(key))
                        {
                            Log.Write("ACCOUNT", "   refused: empty name or key is not a 32-digit hex value");
                            Rmc.Error(s, c, q, QResult.Core_InvalidArgument);
                            return true;
                        }
                        Account a = Accounts.Create(name, key);
                        if (a == null)
                        {
                            Log.Write("ACCOUNT", "   username already exists");
                            Rmc.Error(s, c, q, QResult.RendezVous_UsernameAlreadyExists);
                            return true;
                        }
                        Log.Write("ACCOUNT", "   created pid " + a.Pid);
                        Rmc.Respond(s, c, q, new QWriter().U32(QResult.Success).ToArray());
                        return true;
                    }
                case ChangePassword:
                    {
                        string key = r.String();
                        Account a = Accounts.Find(c.Pid);
                        if (a == null || a.Pid == Config.GuestPid || !Crypto.IsKeyHex(key)) { Rmc.Error(s, c, q, QResult.Core_InvalidArgument); return true; }
                        Accounts.SetKey(a, key);
                        Log.Write("ACCOUNT", "Password changed for " + a.Username);
                        Rmc.Respond(s, c, q, new QWriter().U32(QResult.Success).ToArray());
                        return true;
                    }
                case GetName:
                    {
                        uint pid = r.U32();
                        Account a = Accounts.Find(pid);
                        Rmc.Respond(s, c, q, new QWriter().String(a != null ? a.Username : "").ToArray());
                        return true;
                    }
            }
            return false;
        }
    }

    // Players behind the same router share a public IP; many routers cannot loop traffic back to their
    // own public address, so such players must reach each other on their LAN addresses.
    public static class Lan
    {
        public static bool SamePublicIp(Connection a, Connection b)
        {
            return a != null && b != null && a.EndPoint.Address.Equals(b.EndPoint.Address);
        }

        // The host's own (local) address that best matches the viewer's local addresses, taken from the
        // station URLs both registered; null if the host registered none.
        public static string LocalAddressOf(Connection host, Connection viewer)
        {
            string best = null;
            int bestScore = -1;
            foreach (string hu in host.StationUrls)
            {
                string ha = SecureService.GetUrlParam(hu, "address");
                if (ha == null) continue;
                int score = 0;
                foreach (string vu in viewer.StationUrls)
                {
                    string va = SecureService.GetUrlParam(vu, "address");
                    if (va != null) score = Math.Max(score, CommonPrefixBits(ha, va));
                }
                if (score > bestScore) { bestScore = score; best = ha; }
            }
            return best;
        }

        static int CommonPrefixBits(string a, string b)
        {
            IPAddress x, y;
            if (!IPAddress.TryParse(a, out x) || !IPAddress.TryParse(b, out y)) return 0;
            byte[] p = x.GetAddressBytes(), q = y.GetAddressBytes();
            if (p.Length != q.Length) return 0;
            int bits = 0;
            for (int i = 0; i < p.Length; i++)
            {
                int diff = p[i] ^ q[i];
                if (diff == 0) { bits += 8; continue; }
                for (int m = 0x80; (diff & m) == 0; m >>= 1) bits++;
                break;
            }
            return bits;
        }
    }

    // NAT traversal (protocol 0x03), Quazal standard method numbers:
    //   1 RequestProbeInitiation(List<StationURL> targets)
    //   2 InitiateProbe(StationURL urlToProbe)                     server -> client
    //   3 RequestProbeInitiationExt(List<StationURL> targets, StationURL urlToProbe)
    //   4 ReportNATTraversalResult, 5 ReportNATProperties, 7 ReportNATTraversalResultDetail
    // A joining player calls 3 with the host's URL ("udp:/address=..;port=9103;RVCID=n") and an empty
    // urlToProbe; the host only answers probes it was told about, so the server forwards InitiateProbe.
    public static class NatTraversalService
    {
        public static bool Handle(PrudpServer s, Connection c, RmcRequest q)
        {
            QReader r = new QReader(q.Params);
            switch (q.MethodId)
            {
                case 1:
                case 3:
                    {
                        List<string> targets = r.StringList();
                        string given = q.MethodId == 3 && r.Remaining >= 2 ? r.String() : "";
                        Log.Write("NAT", "RequestProbeInitiation from " + c + " targets [" + string.Join(" | ", targets.ToArray()) +
                                         "] urlToProbe \"" + given + "\"" + (r.Remaining > 0 ? " extra " + Log.Hex(r.Rest()) : ""));
                        Rmc.Respond(s, c, q, new byte[0]);
                        foreach (string t in targets)
                        {
                            Connection target = FindTarget(s, t);
                            if (target == null) { Log.Write("NAT", "   target not connected: " + t); continue; }
                            string urlToProbe = given.Length > 0 ? given : ProbeUrlOf(c, target);
                            Log.Write("NAT", "   InitiateProbe on " + target + " -> probe " + urlToProbe);
                            Rmc.Call(s, target, Protocols.NATTraversal, 2, new QWriter().String(urlToProbe).ToArray());
                        }
                        return true;
                    }
                case 4:
                case 5:
                case 7:
                    Log.Write("NAT", "method " + q.MethodId + " (report) from " + c + ": " + Log.Hex(q.Params));
                    Rmc.Respond(s, c, q, new byte[0]);
                    return true;
            }
            return false;
        }

        // Same shape the game uses for targets: udp:/address=<ip>;port=<port>;RVCID=<cid>, pointing at the
        // player's game socket: its LAN address when both players share a public IP, otherwise the public
        // endpoint learned from NAT echo.
        static string ProbeUrlOf(Connection c, Connection target)
        {
            string addr = c.EndPoint.Address.ToString(), port = c.EndPoint.Port.ToString();
            string local = Lan.SamePublicIp(c, target) ? Lan.LocalAddressOf(c, target) : null;
            IPEndPoint game = GamePorts.Of(c);
            if (local != null) { addr = local; port = Config.GamePort.ToString(); }
            else if (game != null) { addr = game.Address.ToString(); port = game.Port.ToString(); }
            else if (c.PublicUrl != null)
            {
                addr = SecureService.GetUrlParam(c.PublicUrl, "address") ?? addr;
                port = SecureService.GetUrlParam(c.PublicUrl, "port") ?? port;
            }
            return "udp:/address=" + addr + ";port=" + port + ";RVCID=" + c.ConnectionId;
        }

        static Connection FindTarget(PrudpServer s, string url)
        {
            uint rvcid;
            string v = SecureService.GetUrlParam(url, "RVCID");
            if (v != null && uint.TryParse(v, out rvcid))
            {
                Connection byId = s.FindConnection(x => x.ConnectionId == rvcid && x.Pid != 0);
                if (byId != null) return byId;
            }
            string addr = SecureService.GetUrlParam(url, "address"), port = SecureService.GetUrlParam(url, "port");
            return s.FindConnection(x => x.EndPoint.Address.ToString() == addr && x.EndPoint.Port.ToString() == port);
        }
    }

    // Secure connection service on the secure server (protocol 0x0B).
    public static class SecureService
    {
        const uint Register = 1, RequestConnectionData = 2, RequestUrls = 3, RegisterEx = 4;
        static uint nextCid = 1;

        // CONNECT payload: Buffer(inner ticket) + Buffer(RC4(session key)[pid, cid, check] + HMAC).
        public static byte[] OnConnect(PrudpServer s, Connection c, byte[] payload)
        {
            QReader r = new QReader(payload);
            byte[] ticket = r.Buffer();
            byte[] request = r.Buffer();
            byte[] key; uint pid;
            if (!Kerberos.OpenInnerTicket(ticket, out key, out pid))
            {
                Log.Write("SECURE", "!! ticket not issued by this server (or different format): " + Log.Hex(ticket));
                return null;
            }
            byte[] plain = Kerberos.Open(key, request);
            if (plain == null)
            {
                Log.Write("SECURE", "   request HMAC mismatch, decrypting without check");
                byte[] enc = new byte[Math.Max(0, request.Length - 16)];
                Array.Copy(request, enc, enc.Length);
                plain = Rc4.Once(key, enc);
            }
            Log.Write("SECURE", "   CONNECT request data: " + Log.Hex(plain));
            QReader pr = new QReader(plain);
            uint reqPid = pr.U32();
            uint cid = pr.U32();
            uint check = pr.U32();
            Account a = Accounts.Find(pid);
            c.Pid = pid; c.SessionKey = key;
            if (a != null) c.Username = a.Username;
            Log.Write("SECURE", "   ticket OK: pid=" + pid + " (request pid " + reqPid + ") cid=" + cid + " check=0x" + check.ToString("X8"));
            return new QWriter().Buffer(new QWriter().U32(check + 1).ToArray()).ToArray();
        }

        public static bool Handle(PrudpServer s, Connection c, RmcRequest q)
        {
            QReader r = new QReader(q.Params);
            switch (q.MethodId)
            {
                case Register:
                case RegisterEx:
                    {
                        List<string> urls = r.StringList();
                        if (q.MethodId == RegisterEx) Log.Write("SECURE", "RegisterEx extra data: " + Log.Hex(r.Rest()));
                        c.StationUrls = urls;
                        c.ConnectionId = nextCid++;
                        string pub = urls.Count > 0 ? PublicUrl(urls[0], c) : "prudp:/address=" + c.EndPoint.Address + ";port=" + c.EndPoint.Port + ";sid=15";
                        // The game reads RVCID (and PID) from host URLs before probing a host.
                        pub = SetUrlParam(SetUrlParam(pub, "PID", c.Pid.ToString()), "RVCID", c.ConnectionId.ToString());
                        c.PublicUrl = pub;
                        Log.Write("SECURE", "Register " + c + " urls: " + string.Join(" | ", urls.ToArray()) + " -> public " + pub);
                        Rmc.Respond(s, c, q, new QWriter().U32(QResult.Success).U32(c.ConnectionId).String(pub).ToArray());
                        return true;
                    }
            }
            return false;
        }

        public static string GetUrlParam(string url, string key)
        {
            int sep = url.IndexOf(":/");
            if (sep < 0) return null;
            foreach (string part in url.Substring(sep + 2).Split(';'))
                if (part.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase)) return part.Substring(key.Length + 1);
            return null;
        }

        // Sets (or adds) key=value in a station URL like "prudp:/address=1.2.3.4;port=9103;sid=15".
        public static string SetUrlParam(string url, string key, string value)
        {
            int sep = url.IndexOf(":/");
            if (sep < 0) return url;
            string scheme = url.Substring(0, sep + 2);
            List<string> parts = new List<string>(url.Substring(sep + 2).Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries));
            bool found = false;
            for (int i = 0; i < parts.Count; i++)
                if (parts[i].StartsWith(key + "=", StringComparison.OrdinalIgnoreCase)) { parts[i] = key + "=" + value; found = true; }
            if (!found) parts.Add(key + "=" + value);
            return scheme + string.Join(";", parts.ToArray());
        }

        // Replaces address and port in the client's station URL with what the server actually sees.
        static string PublicUrl(string url, Connection c)
        {
            int sep = url.IndexOf(":/");
            if (sep < 0) return url;
            string scheme = url.Substring(0, sep + 2);
            string[] parts = url.Substring(sep + 2).Split(';');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].StartsWith("address=")) parts[i] = "address=" + c.EndPoint.Address;
                else if (parts[i].StartsWith("port=")) parts[i] = "port=" + c.EndPoint.Port;
            }
            return scheme + string.Join(";", parts);
        }
    }
}
