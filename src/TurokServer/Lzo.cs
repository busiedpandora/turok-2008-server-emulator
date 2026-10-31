using System;
using System.IO;

namespace TurokServer
{
    // LZO1X decompressor (port of the minilzo reference logic). Turok compresses large
    // RMC payloads with LZO1X instead of zlib; the stream ends with the marker 11 00 00.
    public static class Lzo
    {
        public static byte[] Decompress(byte[] src, int offset, int length)
        {
            byte[] dst = new byte[Math.Max(256, length * 8)];
            int op = 0;
            int ip = offset;
            int end = offset + length;
            int t, mPos;

            if (src[ip] > 17)
            {
                t = src[ip++] - 17;
                if (t < 4) goto match_next;
                Copy(src, ref ip, ref dst, ref op, t);
                goto first_literal_run;
            }

        loop:
            t = src[ip++];
            if (t >= 16) goto match;
            if (t == 0)
            {
                while (src[ip] == 0) { t += 255; ip++; }
                t += 15 + src[ip++];
            }
            Copy(src, ref ip, ref dst, ref op, t + 3);

        first_literal_run:
            t = src[ip++];
            if (t >= 16) goto match;
            mPos = op - (1 + 0x0800) - (t >> 2) - (src[ip++] << 2);
            CopyMatch(ref dst, ref op, mPos, 3);
            goto match_done;

        match:
            if (t >= 64)
            {
                mPos = op - 1 - ((t >> 2) & 7) - (src[ip++] << 3);
                t = (t >> 5) - 1;
                CopyMatch(ref dst, ref op, mPos, t + 2);
                goto match_done;
            }
            else if (t >= 32)
            {
                t &= 31;
                if (t == 0)
                {
                    while (src[ip] == 0) { t += 255; ip++; }
                    t += 31 + src[ip++];
                }
                mPos = op - 1 - ((src[ip] | (src[ip + 1] << 8)) >> 2);
                ip += 2;
            }
            else if (t >= 16)
            {
                mPos = op - ((t & 8) << 11);
                t &= 7;
                if (t == 0)
                {
                    while (src[ip] == 0) { t += 255; ip++; }
                    t += 7 + src[ip++];
                }
                mPos -= (src[ip] | (src[ip + 1] << 8)) >> 2;
                ip += 2;
                if (mPos == op) goto eof;
                mPos -= 0x4000;
            }
            else
            {
                mPos = op - 1 - (t >> 2) - (src[ip++] << 2);
                CopyMatch(ref dst, ref op, mPos, 2);
                goto match_done;
            }
            CopyMatch(ref dst, ref op, mPos, t + 2);

        match_done:
            t = src[ip - 2] & 3;
            if (t == 0) goto loop;

        match_next:
            Copy(src, ref ip, ref dst, ref op, t);
            t = src[ip++];
            goto match;

        eof:
            if (ip != end) throw new InvalidDataException("LZO: " + (end - ip) + " trailing bytes");
            byte[] result = new byte[op];
            Array.Copy(dst, result, op);
            return result;
        }

        static void Ensure(ref byte[] dst, int needed)
        {
            if (needed <= dst.Length) return;
            byte[] n = new byte[Math.Max(needed, dst.Length * 2)];
            Array.Copy(dst, n, dst.Length);
            dst = n;
        }

        static void Copy(byte[] src, ref int ip, ref byte[] dst, ref int op, int count)
        {
            Ensure(ref dst, op + count);
            Array.Copy(src, ip, dst, op, count);
            ip += count; op += count;
        }

        static void CopyMatch(ref byte[] dst, ref int op, int mPos, int count)
        {
            if (mPos < 0) throw new InvalidDataException("LZO: match before start of output");
            Ensure(ref dst, op + count);
            for (int i = 0; i < count; i++) dst[op++] = dst[mPos++];
        }
    }
}
