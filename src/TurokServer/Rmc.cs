using System;
using System.Collections.Generic;
using System.Text;

namespace TurokServer
{
    public static class Protocols
    {
        public const int NATTraversal = 0x03, Authentication = 0x0A, Secure = 0x0B, Notification = 0x0E,
            Friends = 0x14, MatchMaking = 0x15, PersistentStore = 0x18, AccountManagement = 0x19,
            MessageDelivery = 0x1B, News = 0x1F;

        static readonly Dictionary<int, string> names = new Dictionary<int, string>
        {
            {NATTraversal, "NATTraversal"}, {Authentication, "Authentication"}, {Secure, "Secure"},
            {Notification, "Notification"}, {Friends, "Friends"}, {MatchMaking, "MatchMaking"},
            {PersistentStore, "PersistentStore"}, {AccountManagement, "AccountManagement"},
            {MessageDelivery, "MessageDelivery"}, {News, "News"}, {0x64, "Turok"}
        };

        public static string Name(int id)
        {
            string n;
            return names.TryGetValue(id, out n) ? n : "Unknown";
        }
    }

    public static class QResult
    {
        public const uint Success = 0x00010001;
        public const uint Core_NotImplemented = 0x80010002;
        public const uint Core_InvalidArgument = 0x8001000A;
        public const uint RendezVous_InvalidUsername = 0x80030064;
        public const uint RendezVous_InvalidPassword = 0x80030065;
        public const uint RendezVous_UsernameAlreadyExists = 0x80030066;
    }

    public class RmcRequest
    {
        public int Protocol;
        public bool IsRequest;
        public uint CallId, MethodId;
        public byte[] Params;
        public byte[] Raw;

        public static RmcRequest Parse(byte[] msg)
        {
            QReader r = new QReader(msg);
            RmcRequest q = new RmcRequest();
            q.Raw = msg;
            r.U32(); // size
            byte b = r.U8();
            q.IsRequest = (b & 0x80) != 0;
            q.Protocol = b & 0x7F;
            if (q.Protocol == 0x7F) q.Protocol = r.U16();
            if (q.IsRequest)
            {
                q.CallId = r.U32();
                q.MethodId = r.U32();
            }
            q.Params = r.Rest();
            return q;
        }

        public override string ToString()
        {
            return Protocols.Name(Protocol) + "(0x" + Protocol.ToString("X2") + ") method " + MethodId + " call " + CallId;
        }
    }

    public static class Rmc
    {
        public static byte[] Header(int protocol, bool request)
        {
            QWriter w = new QWriter();
            if (protocol < 0x7F) w.U8((byte)(protocol | (request ? 0x80 : 0)));
            else { w.U8((byte)(0x7F | (request ? 0x80 : 0))); w.U16((ushort)protocol); }
            return w.ToArray();
        }

        public static void Respond(PrudpServer s, Connection c, RmcRequest q, byte[] body)
        {
            QWriter inner = new QWriter();
            inner.Bytes(Header(q.Protocol, false)).U8(1).U32(q.CallId).U32(q.MethodId | 0x8000).Bytes(body);
            byte[] b = inner.ToArray();
            QWriter msg = new QWriter().U32((uint)b.Length).Bytes(b);
            Log.Write("RMC", "-> " + c + " response to " + q + ": " + Log.Hex(body));
            s.SendMessage(c, msg.ToArray());
        }

        // Server -> client call (the client answers with an RMC response, logged by Dispatch).
        public static void Call(PrudpServer s, Connection c, int protocol, uint method, byte[] body)
        {
            uint callId = ++c.ServerCallId;
            QWriter inner = new QWriter();
            inner.Bytes(Header(protocol, true)).U32(callId).U32(method).Bytes(body);
            byte[] b = inner.ToArray();
            QWriter msg = new QWriter().U32((uint)b.Length).Bytes(b);
            Log.Write("RMC", "=> " + c + " CALL " + Protocols.Name(protocol) + "(0x" + protocol.ToString("X2") + ") method " + method +
                             " call " + callId + ": " + Log.Hex(body));
            s.SendMessage(c, msg.ToArray());
        }

        public static void Error(PrudpServer s, Connection c, RmcRequest q, uint error)
        {
            QWriter inner = new QWriter();
            inner.Bytes(Header(q.Protocol, false)).U8(0).U32(error).U32(q.CallId);
            byte[] b = inner.ToArray();
            QWriter msg = new QWriter().U32((uint)b.Length).Bytes(b);
            Log.Write("RMC", "-> " + c + " ERROR 0x" + error.ToString("X8") + " to " + q);
            s.SendMessage(c, msg.ToArray());
        }

        public static void Dispatch(PrudpServer s, Connection c, byte[] msg)
        {
            RmcRequest q;
            try { q = RmcRequest.Parse(msg); }
            catch (Exception ex) { Log.Write("RMC", "!! malformed RMC message (" + ex.Message + "): " + Log.Hex(msg)); return; }

            if (!q.IsRequest)
            {
                // Response layout: u8 success, then (u32 callId, u32 method|0x8000, data) or (u32 error, u32 callId).
                Log.Write("RMC", "<= " + c + " RESPONSE from client to our call, protocol " + Protocols.Name(q.Protocol) + ": " + Log.Hex(q.Params));
                return;
            }

            bool secret = q.Protocol == Protocols.AccountManagement && (q.MethodId == 1 || q.MethodId == 21);
            if (secret)
                Log.Write("RMC", "<- " + c + " " + q + " params hidden (contain the plain password)");
            else
            {
                Log.Write("RMC", "<- " + c + " " + q + " params: " + Log.Hex(q.Params));
                List<string> strs = FindStrings(q.Params);
                if (strs.Count > 0) Log.Write("RMC", "   strings: \"" + string.Join("\", \"", strs.ToArray()) + "\"");
            }

            try
            {
                bool handled;
                switch (q.Protocol)
                {
                    case Protocols.Authentication: handled = AuthenticationService.Handle(s, c, q); break;
                    case Protocols.Secure: handled = SecureService.Handle(s, c, q); break;
                    case Protocols.AccountManagement: handled = AccountManagementService.Handle(s, c, q); break;
                    case TurokProtocol.Id: handled = TurokProtocol.Handle(s, c, q); break;
                    case Protocols.NATTraversal: handled = NatTraversalService.Handle(s, c, q); break;
                    case Protocols.MatchMaking: handled = TurokProtocol.HandleMatchMaking(s, c, q); break;
                    default: handled = false; break;
                }
                if (!handled)
                {
                    Log.Write("RMC", "!! NOT IMPLEMENTED: " + q + " (answering Core::NotImplemented)");
                    Error(s, c, q, QResult.Core_NotImplemented);
                }
            }
            catch (Exception ex)
            {
                Log.Write("RMC", "!! handler crashed for " + q + ": " + ex);
                Error(s, c, q, QResult.Core_InvalidArgument);
            }
        }

        // Finds Quazal strings (u16 length incl. NUL + ASCII) to make logs readable.
        public static List<string> FindStrings(byte[] b)
        {
            List<string> res = new List<string>();
            int o = 0;
            while (o + 2 < b.Length)
            {
                int len = BitConverter.ToUInt16(b, o);
                if (len >= 2 && o + 2 + len <= b.Length && b[o + 2 + len - 1] == 0)
                {
                    bool ok = true;
                    for (int i = 0; i < len - 1; i++)
                        if (b[o + 2 + i] < 0x20 || b[o + 2 + i] > 0x7E) { ok = false; break; }
                    if (ok) { res.Add(Encoding.ASCII.GetString(b, o + 2, len - 1)); o += 2 + len; continue; }
                }
                o++;
            }
            return res;
        }
    }
}
