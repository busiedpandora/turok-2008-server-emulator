using System;
using System.Collections.Generic;
using System.IO;

namespace TurokServer
{
    public class Account
    {
        public uint Pid;
        public string Username;
        // Account key as sent by the game in CreateAccount: hex of MD5 applied 65000 times to the password.
        public string KeyHex;

        public byte[] BaseKey { get { return Crypto.FromHex(KeyHex); } }
    }

    // Minimal account store: accounts.txt, one "pid;username;keyhex" per line.
    public static class Accounts
    {
        static readonly Dictionary<string, Account> byName = new Dictionary<string, Account>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<uint, Account> byPid = new Dictionary<uint, Account>();
        static string path;
        static uint nextPid = 1000;

        public static void Load(string file)
        {
            path = file;
            Add(new Account { Pid = Config.GuestPid, Username = Config.GuestUser, KeyHex = Crypto.ToHex(Crypto.BaseKey(Config.GuestPassword)) }, false);
            if (!File.Exists(file)) return;
            foreach (string line in File.ReadAllLines(file))
            {
                string[] f = line.Split(';');
                if (f.Length < 3) continue;
                uint pid;
                if (!uint.TryParse(f[0], out pid)) continue;
                if (!Crypto.IsKeyHex(f[2])) { Log.Write("ACCOUNTS", "Skipping " + f[1] + ": key is not a 32-digit hex value"); continue; }
                Add(new Account { Pid = pid, Username = f[1], KeyHex = f[2].ToLowerInvariant() }, false);
                if (pid >= nextPid) nextPid = pid + 1;
            }
            Log.Write("ACCOUNTS", "Loaded " + (byName.Count - 1) + " accounts from " + file);
        }

        public static Account Find(string name)
        {
            Account a; return byName.TryGetValue(name, out a) ? a : null;
        }

        public static Account Find(uint pid)
        {
            Account a; return byPid.TryGetValue(pid, out a) ? a : null;
        }

        public static Account Create(string name, string keyHex)
        {
            if (Find(name) != null) return null;
            Account a = new Account { Pid = nextPid++, Username = name, KeyHex = keyHex.ToLowerInvariant() };
            Add(a, true);
            return a;
        }

        public static void SetKey(Account a, string keyHex)
        {
            a.KeyHex = keyHex.ToLowerInvariant();
            Save();
        }

        static void Add(Account a, bool save)
        {
            byName[a.Username] = a;
            byPid[a.Pid] = a;
            if (save) Save();
        }

        static void Save()
        {
            if (path == null) return;
            List<string> lines = new List<string>();
            foreach (Account a in byPid.Values)
                if (a.Pid != Config.GuestPid) lines.Add(a.Pid + ";" + a.Username + ";" + a.KeyHex);
            File.WriteAllLines(path, lines.ToArray());
        }
    }
}
