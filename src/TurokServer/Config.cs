using System;
using System.IO;

namespace TurokServer
{
    // Settings can be overridden in server.ini (key=value lines) next to the executable.
    public static class Config
    {
        public static string AccessKey = "gTy3mT5s";
        public static string GuestUser = "GUEST";
        public static string GuestPassword = "h7fyctiuucf";
        public static uint GuestPid = 100;

        public static int AuthPort = 30720;
        public static int SecurePort = 30721;
        public static int WellKnownPort = 9103;

        // Address written into the station URLs the game receives (secure server URL).
        // 127.0.0.1 for tests on this PC, the LAN IP for a LAN, the public IP (or a DNS name, resolved
        // at startup) on a VPS.
        public static string PublicAddress = "127.0.0.1";

        // Local UDP port of the game socket (UE3 game port). Used for players sharing a public IP,
        // who must reach each other on their LAN addresses.
        public static int GamePort = 7777;

        // Protection: connections accepted per source IP and server, and largest datagram handled.
        public static int MaxConnectionsPerIp = 16;
        public static int MaxDatagramSize = 2048;

        // Logging: packet-level lines (<< / >>) are very verbose; files rotate at LogMaxMB and only the
        // newest LogKeepFiles are kept.
        public static bool LogPackets = true;
        public static int LogMaxMB = 20;
        public static int LogKeepFiles = 30;

        // Experiments on the Turok search method (protocol 0x64 method 6):
        //   SearchReply = list | error | error-when-empty
        //   FakeGathering = true adds a fake match to every search result, to see how the game joins.
        public static string SearchReply = "list";

        // The game itself uses the well-known port 9103 for peer-to-peer traffic; listening on it
        // here would steal it from a game running on the same PC. Only for diagnostics.
        public static bool WellKnownLogger = false;
        public static bool FakeGathering = false;

        public const uint AuthServerPid = 1;
        public const uint SecureServerPid = 2;

        public static byte ChecksumSetting
        {
            get
            {
                int sum = 0;
                foreach (char c in AccessKey) sum += (byte)c;
                return (byte)sum;
            }
        }

        public static void Load(string path)
        {
            if (!File.Exists(path)) return;
            foreach (string raw in File.ReadAllLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(";") || line.StartsWith("#")) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string k = line.Substring(0, eq).Trim();
                string v = line.Substring(eq + 1).Trim();
                switch (k)
                {
                    case "AccessKey": AccessKey = v; break;
                    case "GuestUser": GuestUser = v; break;
                    case "GuestPassword": GuestPassword = v; break;
                    case "GuestPid": GuestPid = uint.Parse(v); break;
                    case "AuthPort": AuthPort = int.Parse(v); break;
                    case "SecurePort": SecurePort = int.Parse(v); break;
                    case "WellKnownPort": WellKnownPort = int.Parse(v); break;
                    case "PublicAddress": PublicAddress = v; break;
                    case "SearchReply": SearchReply = v.ToLowerInvariant(); break;
                    case "WellKnownLogger": WellKnownLogger = v == "1" || v.ToLowerInvariant() == "true"; break;
                    case "FakeGathering": FakeGathering = v == "1" || v.ToLowerInvariant() == "true"; break;
                    case "GamePort": GamePort = int.Parse(v); break;
                    case "MaxConnectionsPerIp": MaxConnectionsPerIp = int.Parse(v); break;
                    case "MaxDatagramSize": MaxDatagramSize = int.Parse(v); break;
                    case "LogPackets": LogPackets = v == "1" || v.ToLowerInvariant() == "true"; break;
                    case "LogMaxMB": LogMaxMB = int.Parse(v); break;
                    case "LogKeepFiles": LogKeepFiles = int.Parse(v); break;
                    default: Log.Write("CONFIG", "Unknown setting ignored: " + k); break;
                }
            }
        }
    }
}
