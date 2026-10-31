using System;
using System.Security.Cryptography;

namespace TurokServer
{
    // Quazal Kerberos-like tickets.
    //
    // Ticket given to the client (encrypted with the key derived from the user's password):
    //   [session key 16][target pid u32][Buffer inner ticket]  RC4  + HMAC-MD5
    // Inner ticket (opaque to the client, encrypted with the secure server key):
    //   [session key 16][user pid u32][issued ticks u64]        RC4  + HMAC-MD5
    public static class Kerberos
    {
        public const int SessionKeyLength = 16;
        static readonly byte[] ServerKey = Crypto.DeriveKey(Config.SecureServerPid, "TurokEmuSecureServer");

        public static byte[] NewSessionKey()
        {
            byte[] k = new byte[SessionKeyLength];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(k);
            return k;
        }

        public static byte[] BuildClientTicket(Account user, uint targetPid, byte[] sessionKey)
        {
            byte[] inner = Seal(ServerKey, new QWriter().Bytes(sessionKey).U32(user.Pid).U64((ulong)DateTime.UtcNow.Ticks).ToArray());
            byte[] plain = new QWriter().Bytes(sessionKey).U32(targetPid).Buffer(inner).ToArray();
            return Seal(Crypto.UserKey(user.Pid, user.BaseKey), plain);
        }

        // Returns false if the inner ticket was not issued by this server.
        public static bool OpenInnerTicket(byte[] sealedTicket, out byte[] sessionKey, out uint userPid)
        {
            sessionKey = null; userPid = 0;
            byte[] plain = Open(ServerKey, sealedTicket);
            if (plain == null || plain.Length < SessionKeyLength + 4) return false;
            QReader r = new QReader(plain);
            sessionKey = r.Bytes(SessionKeyLength);
            userPid = r.U32();
            return true;
        }

        public static byte[] Seal(byte[] key, byte[] plain)
        {
            byte[] enc = Rc4.Once(key, plain);
            byte[] mac = Crypto.HmacMd5(key, enc);
            return new QWriter().Bytes(enc).Bytes(mac).ToArray();
        }

        public static byte[] Open(byte[] key, byte[] sealedData)
        {
            if (sealedData.Length < 16) return null;
            byte[] enc = new byte[sealedData.Length - 16];
            Array.Copy(sealedData, enc, enc.Length);
            byte[] mac = Crypto.HmacMd5(key, enc);
            for (int i = 0; i < 16; i++)
                if (mac[i] != sealedData[enc.Length + i]) return null;
            return Rc4.Once(key, enc);
        }
    }
}
