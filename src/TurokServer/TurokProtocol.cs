using System;
using System.Collections.Generic;
using System.Text;

namespace TurokServer
{
    // Quazal Gathering as serialized by Turok (base part of TurokGathering).
    public class Gathering
    {
        public uint Id, Owner, Host;
        public ushort MinParticipants, MaxParticipants;
        public uint ParticipationPolicy, PolicyArgument, Flags, State;
        public string Description = "";
        public string ClassName = "TurokGathering";

        // TurokGathering tail (14 bytes). Meaning of the bytes from 0x820CA0 (gathering -> UE3 game settings):
        //   u32 Unknown1 (always 100), u32 Unknown2 (always 1),
        //   u8 PublicSlots (0: slots are private connections, else public), u8 OpenSlots (free slots),
        //   u8 Category (1 team, 2 free-for-all, 3 coop), u8 Mode (game type), u8 Large (1 = 16 players),
        //   u8 Unknown4 (always 1, used as a map/playlist index)
        // Hosts register with OpenSlots = 0, so the server must fill it in or every match looks full.
        public uint Unknown1 = 100, Unknown2 = 1;
        public byte PublicSlots, OpenSlots;
        public byte Category, Mode, Large, Unknown4 = 1;
        public byte[] ExtraTail = new byte[0]; // anything after the known 14 bytes

        // Server-side info about the host, returned by searches.
        public string OwnerName = "";
        public List<string> Urls = new List<string>();
        public Connection OwnerConnection;

        public static Gathering Read(QReader r, int dataLength)
        {
            int start = r.Position;
            Gathering g = new Gathering();
            g.Id = r.U32(); g.Owner = r.U32(); g.Host = r.U32();
            g.MinParticipants = r.U16(); g.MaxParticipants = r.U16();
            g.ParticipationPolicy = r.U32(); g.PolicyArgument = r.U32();
            g.Flags = r.U32(); g.State = r.U32();
            g.Description = r.String();
            if (dataLength - (r.Position - start) >= 14)
            {
                g.Unknown1 = r.U32(); g.Unknown2 = r.U32(); g.PublicSlots = r.U8(); g.OpenSlots = r.U8();
                g.Category = r.U8(); g.Mode = r.U8(); g.Large = r.U8(); g.Unknown4 = r.U8();
            }
            g.ExtraTail = r.Bytes(dataLength - (r.Position - start));
            return g;
        }

        public byte[] Write()
        {
            return new QWriter().U32(Id).U32(Owner).U32(Host).U16(MinParticipants).U16(MaxParticipants)
                .U32(ParticipationPolicy).U32(PolicyArgument).U32(Flags).U32(State).String(Description)
                .U32(Unknown1).U32(Unknown2).U8(PublicSlots).U8(OpenSlots).U8(Category).U8(Mode).U8(Large).U8(Unknown4)
                .Bytes(ExtraTail).ToArray();
        }

        // AnyDataHolder: String className, u32 (len + 4), u32 len, data.
        public byte[] WriteAnyData()
        {
            byte[] d = Write();
            return new QWriter().String(ClassName).U32((uint)d.Length + 4).U32((uint)d.Length).Bytes(d).ToArray();
        }

        public string Playlist
        {
            get
            {
                switch (Category)
                {
                    case 1: return Large != 0 ? "LARGE TEAM GAME" : "SMALL TEAM GAME";
                    case 2: return Large != 0 ? "LARGE FFA" : "SMALL FFA";
                    case 3: return "COOP";
                    default: return "category " + Category;
                }
            }
        }

        public override string ToString()
        {
            return "Gathering id=0x" + Id.ToString("X") + " owner=" + Owner + " host=" + Host + " players=" + MinParticipants + "-" + MaxParticipants +
                   " policy=" + ParticipationPolicy + "/" + PolicyArgument + " flags=0x" + Flags.ToString("X") + " state=" + State +
                   " playlist=" + Playlist + " mode=" + Mode + " open=" + OpenSlots + (PublicSlots != 0 ? " public" : " private") +
                   " unk=" + Unknown1 + "/" + Unknown2 + "/" + Unknown4 +
                   (ExtraTail.Length > 0 ? " extra=[" + Log.Hex(ExtraTail) + "]" : "");
        }
    }

    // Turok's own protocol (id 0x64 = 100, TurokProtocolClient in the game binary).
    // Method names are not in the binary. Response formats come from the client's response
    // dispatcher (unpacked image, 0x826790, jump table at 0x8268C4):
    //   1, 3        -> u32
    //   2, 4, 5, 7  -> nothing
    //   6, 9        -> List<AnyDataHolder<Gathering>>, List<String>, List<GatheringURLs>   (reader 0x827270)
    //   8           -> AnyDataHolder<Gathering>, String, GatheringURLs              (reader 0x827980)
    //   10          -> List<{u32, u32}>, List<...>                                  (reader 0x826E10)
    //   11, 12      -> List<{u32, u32, u32, u32, String, ...}> (leaderboards?)      (reader 0x8269F0)
    // Meaning from traffic: 1 register gathering, 2 unregister gathering, 6 search, 9 unknown search (once at start).
    public static class TurokProtocol
    {
        public const int Id = 0x64;
        const uint RegisterGathering = 1, UnregisterGathering = 2, JoinGathering = 5, SearchGatherings = 6, SearchAtStart = 9;
        public const uint FakeOwnerPid = 999;

        static readonly Dictionary<uint, Gathering> gatherings = new Dictionary<uint, Gathering>();
        static uint nextGatheringId = 0x1000;

        // Players who joined a host (method 5), by host pid. A host keeps re-registering its gathering
        // while waiting in the lobby, so participants follow the host, not a gathering id.
        static readonly Dictionary<uint, HashSet<uint>> participants = new Dictionary<uint, HashSet<uint>>();
        // Owner of every gathering id ever registered, to resolve joins/leaves on ids already replaced.
        static readonly Dictionary<uint, uint> ownerOfId = new Dictionary<uint, uint>();

        static int JoinedCount(uint host)
        {
            HashSet<uint> set;
            return participants.TryGetValue(host, out set) ? set.Count : 0;
        }

        static void UpdateOpenSlots(Gathering g)
        {
            int open = g.MaxParticipants - 1 - JoinedCount(g.Owner);
            g.OpenSlots = (byte)Math.Max(0, Math.Min(255, open));
        }

        public static bool Handle(PrudpServer s, Connection c, RmcRequest q)
        {
            QReader r = new QReader(q.Params);
            switch (q.MethodId)
            {
                case RegisterGathering:
                    {
                        string cls = r.String();
                        r.U32();
                        int len = (int)r.U32();
                        Gathering g = Gathering.Read(r, len);
                        g.ClassName = cls;
                        byte[] extra = r.Rest();
                        g.Id = nextGatheringId++;
                        g.Owner = c.Pid;
                        g.Host = c.Pid;
                        UpdateOpenSlots(g); // hosts send 0; server keeps max - host - joined players
                        ownerOfId[g.Id] = g.Owner;
                        g.OwnerName = c.Username ?? "";
                        g.OwnerConnection = c;
                        g.Urls = HostUrls(c, null);
                        gatherings[g.Id] = g;
                        Log.Write("TUROK", "RegisterGathering by " + c + ": " + g + " args=[" + Log.Hex(extra) + "]");
                        Rmc.Respond(s, c, q, new QWriter().U32(g.Id).ToArray());
                        return true;
                    }

                case UnregisterGathering:
                    {
                        uint id = r.U32();
                        byte flag = r.Remaining > 0 ? r.U8() : (byte)0;
                        uint owner;
                        if (ownerOfId.TryGetValue(id, out owner) && owner != c.Pid)
                        {
                            // A participant leaving the host's match.
                            HashSet<uint> set;
                            if (participants.TryGetValue(owner, out set)) set.Remove(c.Pid);
                            Log.Write("TUROK", c + " left the match of pid " + owner + " (gathering 0x" + id.ToString("X") + "), " + JoinedCount(owner) + " joined player(s) left");
                            RefreshOwner(owner);
                        }
                        else
                        {
                            bool removed = gatherings.Remove(id);
                            Log.Write("TUROK", "UnregisterGathering 0x" + id.ToString("X") + " flag=" + flag + (removed ? "" : " (unknown id)"));
                        }
                        Rmc.Respond(s, c, q, new byte[0]);
                        return true;
                    }

                case JoinGathering:
                    {
                        // u32 gathering id + u8; sent by the joining player after NAT traversal succeeds.
                        uint id = r.U32();
                        byte flag = r.Remaining > 0 ? r.U8() : (byte)0;
                        uint owner;
                        if (!ownerOfId.TryGetValue(id, out owner))
                            Log.Write("TUROK", "Join by " + c + " of unknown gathering 0x" + id.ToString("X"));
                        else if (owner != c.Pid)
                        {
                            HashSet<uint> set;
                            if (!participants.TryGetValue(owner, out set)) participants[owner] = set = new HashSet<uint>();
                            set.Add(c.Pid);
                            Log.Write("TUROK", c + " joined the match of pid " + owner + " (gathering 0x" + id.ToString("X") + " flag=" + flag + "), " + set.Count + " joined player(s)");
                            RefreshOwner(owner);
                        }
                        Rmc.Respond(s, c, q, new byte[0]);
                        return true;
                    }

                case SearchAtStart:
                    {
                        Log.Write("TUROK", "Method 9 (search at start) by " + c + ", params " + Log.Hex(q.Params) + " -> no results");
                        Rmc.Respond(s, c, q, SearchResult(new List<Gathering>()));
                        return true;
                    }

                case SearchGatherings:
                    {
                        // Inferred layout: u8 max results, u32 (100), u32 (1), u8 (1), u8 category, u8 size
                        // size: 0xFF = any (QUICK MATCH), 0 = small, 1 = large (CUSTOM MATCH), same as Gathering.Large.
                        byte max = r.U8();
                        uint u1 = r.U32(), u2 = r.U32();
                        byte u3 = r.U8(), category = r.U8(), size = r.U8();
                        c.LastSearch = DateTime.Now; // the NAT echo test that follows belongs to this player
                        List<Gathering> found = new List<Gathering>();
                        foreach (Gathering g in gatherings.Values)
                        {
                            if (g.Owner == c.Pid) continue;
                            if (g.Category != category) continue;
                            if (size != 0xFF && g.Large != size) continue;
                            if (g.OpenSlots == 0) continue; // full
                            found.Add(g);
                            if (found.Count >= max) break;
                        }
                        if (Config.FakeGathering && found.Count < max) found.Add(MakeFake(category, size));

                        Log.Write("TUROK", "Search by " + c + ": max=" + max + " category=" + category + " size=" + (size == 0xFF ? "any" : (size == 0 ? "small" : "large")) +
                                  " unk=" + u1 + "/" + u2 + "/" + u3 + " -> " + found.Count + " result(s)");
                        if (Config.SearchReply == "error" || (found.Count == 0 && Config.SearchReply == "error-when-empty"))
                            return false;

                        // URLs depend on who is asking (LAN address for players behind the same router).
                        List<List<string>> urls = new List<List<string>>();
                        foreach (Gathering g in found)
                        {
                            List<string> u = g.OwnerConnection != null ? HostUrls(g.OwnerConnection, c) : g.Urls;
                            urls.Add(u);
                            Log.Write("TUROK", "   result " + g + " owner \"" + g.OwnerName + "\" urls " + string.Join(" | ", u.ToArray()));
                        }
                        Rmc.Respond(s, c, q, SearchResult(found, urls));
                        return true;
                    }

                case 8:
                    {
                        // Single gathering with host name and URLs. Parameters not seen yet:
                        // assume the first u32 is the gathering id.
                        Log.Write("TUROK", "method 8 by " + c + ", params " + Log.Hex(q.Params));
                        Gathering g = null;
                        if (q.Params.Length >= 4) gatherings.TryGetValue(BitConverter.ToUInt32(q.Params, 0), out g);
                        if (g == null) { Log.Write("TUROK", "   no gathering matches the first parameter"); return false; }
                        List<string> gu = g.OwnerConnection != null ? HostUrls(g.OwnerConnection, c) : g.Urls;
                        QWriter w = new QWriter().Bytes(g.WriteAnyData()).String(g.OwnerName).U32(g.Id).StringList(gu);
                        Rmc.Respond(s, c, q, w.ToArray());
                        return true;
                    }

                case 4:
                case 7:
                    // The client reads nothing back from these methods; meaning still unknown.
                    Log.Write("TUROK", "method " + q.MethodId + " (void reply) by " + c + ", params " + Log.Hex(q.Params));
                    Rmc.Respond(s, c, q, new byte[0]);
                    return true;
            }
            Log.Write("TUROK", "method " + q.MethodId + " not understood yet, params: " + Log.Hex(q.Params));
            return false;
        }

        // URLs given to players who find this host. The game probes the FIRST URL (address, port and
        // RVCID, see FPCAsyncTaskFindGames at 0x81E370 and 0x820CA0) from its game socket, and probes are
        // answered on the game socket too. First URL: the host's LAN game address when the viewer shares
        // its public IP, otherwise its public game endpoint learned from NAT echo; then the public URL
        // seen by the server and the host's own URLs. Every URL carries the host's PID and RVCID.
        static List<string> HostUrls(Connection c, Connection viewer)
        {
            List<string> urls = new List<string>();
            string suffix = ";sid=15;PID=" + c.Pid + ";RVCID=" + c.ConnectionId;
            string local = Lan.SamePublicIp(c, viewer) ? Lan.LocalAddressOf(c, viewer) : null;
            if (local != null)
                urls.Add("prudp:/address=" + local + ";port=" + Config.GamePort + suffix);
            System.Net.IPEndPoint game = GamePorts.Of(c);
            if (game != null)
            {
                string pub = "prudp:/address=" + game.Address + ";port=" + game.Port + suffix;
                if (!urls.Contains(pub)) urls.Add(pub);
            }
            if (c.PublicUrl != null && !urls.Contains(c.PublicUrl)) urls.Add(c.PublicUrl);
            foreach (string u in c.StationUrls)
            {
                string full = SecureService.SetUrlParam(SecureService.SetUrlParam(u, "PID", c.Pid.ToString()), "RVCID", c.ConnectionId.ToString());
                if (!urls.Contains(full)) urls.Add(full);
            }
            return urls;
        }

        // List<AnyDataHolder<Gathering>>, List<String> (host name per gathering), List<GatheringURLs>.
        // GatheringURLs = u32 gathering id + List<StationURL as String>.
        static byte[] SearchResult(List<Gathering> found)
        {
            List<List<string>> urls = new List<List<string>>();
            foreach (Gathering g in found) urls.Add(g.Urls);
            return SearchResult(found, urls);
        }

        static byte[] SearchResult(List<Gathering> found, List<List<string>> urls)
        {
            QWriter w = new QWriter();
            w.U32((uint)found.Count);
            foreach (Gathering g in found) w.Bytes(g.WriteAnyData());
            w.U32((uint)found.Count);
            foreach (Gathering g in found) w.String(g.OwnerName);
            w.U32((uint)found.Count);
            for (int i = 0; i < found.Count; i++) w.U32(found[i].Id).StringList(urls[i]);
            return w.ToArray();
        }

        static Gathering MakeFake(byte category, byte size)
        {
            Gathering g = new Gathering();
            g.Id = 0x9999;
            g.Owner = FakeOwnerPid; g.Host = FakeOwnerPid;
            g.MinParticipants = 2;
            g.Category = category == 0 ? (byte)1 : category;
            g.Mode = 1;
            g.Large = (byte)(g.Category == 3 ? 0 : (size == 0xFF ? 1 : size));
            g.MaxParticipants = (ushort)(g.Category == 3 ? 4 : 16);
            g.OpenSlots = (byte)(g.MaxParticipants - 1);
            g.ParticipationPolicy = 100;
            g.OwnerName = "FakeHost";
            g.Urls.Add("prudp:/address=127.0.0.1;port=9;sid=15;PID=" + FakeOwnerPid + ";RVCID=9999");
            return g;
        }

        // MatchMaking (0x15) method 30 SetState(u32 gathering id, u32 state) -> bool (client reader 0xA95ED0).
        // Sent by the host: state 2 when the match starts, 6 when the host leaves it.
        public static bool HandleMatchMaking(PrudpServer s, Connection c, RmcRequest q)
        {
            if (q.MethodId != 30) return false;
            QReader r = new QReader(q.Params);
            uint id = r.U32();
            uint state = r.U32();
            Gathering g;
            bool known = gatherings.TryGetValue(id, out g);
            if (known) g.State = state;
            Log.Write("TUROK", "SetState gathering 0x" + id.ToString("X") + " -> " + state +
                      (state == 2 ? " (match started)" : state == 6 ? " (match ended)" : "") + (known ? "" : " (unknown id)") + " by " + c);
            Rmc.Respond(s, c, q, new QWriter().Bool(true).ToArray());
            return true;
        }

        static void RefreshOwner(uint owner)
        {
            foreach (Gathering g in gatherings.Values)
                if (g.Owner == owner) UpdateOpenSlots(g);
        }

        // Called when a player disconnects: their gatherings disappear, their joined players are
        // released, and they leave any match they had joined.
        public static void RemoveOwnedBy(uint pid)
        {
            List<uint> ids = new List<uint>();
            foreach (KeyValuePair<uint, Gathering> kv in gatherings)
                if (kv.Value.Owner == pid) ids.Add(kv.Key);
            foreach (uint id in ids) gatherings.Remove(id);
            if (ids.Count > 0) Log.Write("TUROK", "Removed " + ids.Count + " gathering(s) of pid " + pid);
            participants.Remove(pid);
            foreach (KeyValuePair<uint, HashSet<uint>> kv in new List<KeyValuePair<uint, HashSet<uint>>>(participants))
                if (kv.Value.Remove(pid)) RefreshOwner(kv.Key);
        }
    }
}
