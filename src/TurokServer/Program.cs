using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace TurokServer
{
    static class Program
    {
        static int Main(string[] args)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            Config.Load(Path.Combine(baseDir, "server.ini"));
            Log.Open(Path.Combine(baseDir, "logs"));
            if (!ResolvePublicAddress()) return 1;
            Accounts.Load(Path.Combine(baseDir, "accounts.txt"));

            Log.Write("MAIN", "Turok 2008 Rendez-Vous emulator");
            Log.Write("MAIN", "Access key " + Config.AccessKey + ", checksum setting 0x" + Config.ChecksumSetting.ToString("X2") +
                              ", public address " + Config.PublicAddress);
            Log.Write("MAIN", "Search reply mode: " + Config.SearchReply + (Config.FakeGathering ? ", FAKE GATHERING ENABLED (experiment)" : ""));

            try
            {
                PrudpServer auth = new PrudpServer("AUTH", Config.AuthPort, Config.AuthServerPid, 0x00011000);
                auth.OnMessage = Rmc.Dispatch;
                auth.Start();

                PrudpServer secure = new PrudpServer("SECURE", Config.SecurePort, Config.SecureServerPid, 0x00022000);
                secure.OnMessage = Rmc.Dispatch;
                secure.OnConnectPayload = SecureService.OnConnect;
                secure.OnDisconnect = (srv, c) => { if (c.Pid != 0) TurokProtocol.RemoveOwnedBy(c.Pid); };
                secure.Start();
            }
            catch (SocketException ex)
            {
                Log.Write("MAIN", "!! Cannot open a UDP port: " + ex.Message + " (is PacketProbe or another server still running?)");
                return 1;
            }

            if (Config.WellKnownLogger) StartRawLogger("WELLKNOWN", Config.WellKnownPort);
            Log.Write("MAIN", "Ready. Press Ctrl+C to stop.");
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }

        // Station URLs need an IP address: a DNS name in PublicAddress is resolved once at startup.
        static bool ResolvePublicAddress()
        {
            IPAddress ip;
            if (IPAddress.TryParse(Config.PublicAddress, out ip)) return true;
            try
            {
                foreach (IPAddress a in Dns.GetHostAddresses(Config.PublicAddress))
                {
                    if (a.AddressFamily != AddressFamily.InterNetwork) continue;
                    Log.Write("MAIN", "PublicAddress " + Config.PublicAddress + " resolved to " + a);
                    Config.PublicAddress = a.ToString();
                    return true;
                }
                Log.Write("MAIN", "!! PublicAddress " + Config.PublicAddress + " has no IPv4 address");
            }
            catch (Exception ex) { Log.Write("MAIN", "!! cannot resolve PublicAddress " + Config.PublicAddress + ": " + ex.Message); }
            return false;
        }

        // Port 9103 purpose is still unknown: only log what arrives.
        static void StartRawLogger(string name, int port)
        {
            UdpClient u;
            try { u = new UdpClient(new IPEndPoint(IPAddress.Any, port)); }
            catch (Exception ex) { Log.Write(name, "!! cannot bind " + port + ": " + ex.Message); return; }
            Thread t = new Thread(() =>
            {
                while (true)
                {
                    IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    try
                    {
                        byte[] d = u.Receive(ref ep);
                        Log.Write(name, "<< " + ep + " " + d.Length + " bytes: " + Log.Hex(d));
                    }
                    catch (Exception ex) { Log.Write(name, "receive error: " + ex.Message); }
                }
            });
            t.IsBackground = true;
            t.Start();
            Log.Write(name, "Logging raw UDP on " + port);
        }
    }
}
