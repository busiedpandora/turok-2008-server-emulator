using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace TurokServer
{
    // RC4 with persistent state, so it can be used per packet (new instance) or per connection (kept instance).
    public class Rc4
    {
        readonly byte[] s = new byte[256];
        int i, j;

        public Rc4(byte[] key)
        {
            for (int k = 0; k < 256; k++) s[k] = (byte)k;
            for (int k = 0, jj = 0; k < 256; k++)
            {
                jj = (jj + key[k % key.Length] + s[k]) & 255;
                byte t = s[k]; s[k] = s[jj]; s[jj] = t;
            }
        }

        public Rc4(string key) : this(Encoding.ASCII.GetBytes(key)) { }

        public byte[] Process(byte[] data)
        {
            byte[] o = new byte[data.Length];
            for (int k = 0; k < data.Length; k++)
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;
                byte t = s[i]; s[i] = s[j]; s[j] = t;
                o[k] = (byte)(data[k] ^ s[(s[i] + s[j]) & 255]);
            }
            return o;
        }

        public static byte[] Once(byte[] key, byte[] data) { return new Rc4(key).Process(data); }
    }

    public static class Crypto
    {
        public static readonly byte[] DataKey = Encoding.ASCII.GetBytes("CD&ML");

        // Quazal key derivation: MD5 applied (65000 + pid % 1024) times to the password.
        // Split in two steps: the game sends the 65000-iteration "base key" (as hex) in CreateAccount,
        // the ticket key adds pid % 1024 more iterations.
        public static byte[] DeriveKey(uint pid, string password)
        {
            return UserKey(pid, BaseKey(password));
        }

        public static byte[] BaseKey(string password)
        {
            return IterateMd5(Encoding.ASCII.GetBytes(password), 65000);
        }

        public static byte[] UserKey(uint pid, byte[] baseKey)
        {
            return IterateMd5(baseKey, (int)(pid % 1024));
        }

        static byte[] IterateMd5(byte[] data, int count)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] buff = data;
                for (int n = 0; n < count; n++) buff = md5.ComputeHash(buff);
                return buff;
            }
        }

        public static string ToHex(byte[] b)
        {
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        public static byte[] FromHex(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        public static bool IsKeyHex(string s)
        {
            if (s == null || s.Length != 32) return false;
            foreach (char c in s)
                if (!Uri.IsHexDigit(c)) return false;
            return true;
        }

        public static byte[] HmacMd5(byte[] key, byte[] data)
        {
            using (HMACMD5 h = new HMACMD5(key)) return h.ComputeHash(data);
        }

        public static byte[] Inflate(byte[] zlib)
        {
            using (DeflateStream ds = new DeflateStream(new MemoryStream(zlib, 2, zlib.Length - 2), CompressionMode.Decompress))
            {
                MemoryStream o = new MemoryStream();
                ds.CopyTo(o);
                return o.ToArray();
            }
        }
    }
}
