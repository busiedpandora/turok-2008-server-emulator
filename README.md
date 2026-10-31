# Turok (2008) Server Emulator

Quazal Rendez-Vous emulator for the PC version of Turok (2008, Propaganda Games), for game preservation.
Based on the research of the Ghost Recon Online and Ghost Recon Future Soldier backends.

[Small demo video](docs/videos/demo.mp4)

## Known facts

| Item | Value |
|---|---|
| Rendez-Vous host | `turokpclive.quazal.net` |
| Authentication port | UDP 30720 |
| Well-known port | UDP 9103 |
| Access key | `gTy3mT5s` |
| PRUDP checksum setting | `0xD0` (sum of the access key bytes) |
| Guest password | `h7fyctiuucf` |
| Payload encryption | RC4, key `CD&ML` |

## Redirecting the game

The game ignores `RendezvousURL` in `TurokEngine.ini`: a capture showed it always resolves
`turokpclive.quazal.net` through DNS, and today that lookup returns no address, which produces
"Could not connect to the online service". Redirect the name with the Windows hosts file:

```
127.0.0.1 turokpclive.quazal.net
```

`tools\RedirectHosts.bat` adds this line (optionally with another IP as argument) and
`tools\RedirectHosts.bat remove` takes it out again. It asks for administrator rights.

## Confirmed from the game (PacketProbe log, 2026-10-27)

- PRUDP v0, virtual ports `0x3F -> 0x31` (stream type 3), checksum with setting `0xD0`.
- DATA payloads are RC4 with key `CD&ML`, first byte `00` (no compression).
- First call: Authentication (`0x0A`) method 1 `Login("GUEST")`.
- Without an answer the game gives up after 10 seconds (`RendezvousLoginTimeout`).

Confirmed with TurokServer (same day): the full guest flow works. `Login("GUEST")`, then
`RequestTicket(100, 2)`, then CONNECT to the secure server with the ticket (payload RC4/CD&ML
encoded, session key 16 bytes), then `Secure.Register` with the client station URL. RC4 is reset
per packet. Afterwards the game asks to "setup the Quazal Account info for the current profile":
accounts are created from the profile screen (ONLINE ACCOUNT, CREATE ACCOUNT), which is handled
by AccountManagement (`0x19`) `CreateAccount`.

Account keys: `CreateAccount(name, key, groups=0x20, password)`. `key` is the hex of MD5 applied
65000 times to the password; the fourth field carries the plain password and is never stored.
The ticket key is that base key with `pid % 1024` more MD5 iterations, which equals the usual
Quazal derivation (MD5 applied `65000 + pid % 1024` times to the password). `accounts.txt` stores
`pid;username;keyhex`.

Matchmaking (QUICK MATCH reaches the "Searching for game" lobby):

- Large payloads are compressed with **LZO1X** (not zlib); the first payload byte is non-zero.
- The game binary contains Quazal clients for TicketGranting, SecureConnection, AccountManagement,
  MatchMaking, MatchMakingExt, NATTraversal, Competition and a custom **TurokProtocol (`0x64`)** with
  the types `TurokGathering`, `TurokSearch`, `TurokLeaderboardStats`. No DDL metadata is embedded,
  so method names are inferred from traffic.
- Quick match sequence seen so far: `0x64` method 6 (search?), `0x64` method 9 (search?), then
  `0x64` method 1 = register gathering with `AnyDataHolder<TurokGathering>` (Quazal Gathering:
  min 2, max 8, policy 100, plus 14 Turok-specific bytes) and two more fields (`u32 1`, empty string).

Playlist cycle: for each playlist the game calls search (method 6), registers its own gathering
(method 1) when nothing is found, waits, then unregisters it (method 2, `u32 id` + `u8`).
TurokGathering tail: `u32 100, u32 1, u16 0, u8 category (1 team, 2 FFA, 3 coop), u8 mode,
u8 large (16 players), u8 1`.

Response formats were read from the game code. `TurokProtocolClient` vtable is at `0xCE3154` in the
unpacked image; its last virtual function `0x826790` dispatches responses with a jump table at
`0x8268C4` (method id - 0x8001):

| Method | Response |
|---|---|
| 1, 3 | `u32` |
| 2, 4, 5, 7 | empty |
| 6, 9 | `List<AnyDataHolder<Gathering>>`, `List<String>`, `List<GatheringURLs>` |
| 8 | `AnyDataHolder<Gathering>`, `String`, `GatheringURLs` |
| 10 | `List<{u32, u32}>`, second list (not decoded yet) |
| 11, 12 | `List<{u32, u32, u32, u32, String, ...}>` (leaderboards?) |

`GatheringURLs` = `u32 gathering id` + `List<String>` station URLs. Answering search with a single list
crashed the game; the three-list reply is now used, empty lists included.

Two-PC test (2026-10-27): both clients find each other's gathering through search, but the one
that finds a match never contacts the host and gives up after a few seconds. A capture showed no
direct traffic between the PCs; instead each game sends NAT echo packets every 250 ms from its game
port 7777 to the secure server: stream type 7 (NATEcho), type 5, vports `71 -> 71`, payload `44 02`,
checksum setting 0. These come from `RVConnectivityTester.cpp`; `RVNATEcho` (`NATEchoStream.cpp`)
answers by mirroring the payload, so the server now echoes them back unchanged.

QUICK MATCH cycles through the five playlists; CUSTOM MATCH searches a single chosen playlist.
Search parameters: `u8 max results, u32 100, u32 1, u8 1, u8 category, u8 size` where size is
`0xFF` (any, QUICK MATCH), `0` (small) or `1` (large), matching the gathering's large flag.
The game sends only three NAT echoes and stops once they are answered.

How search results are used (`FPCAsyncTaskFindGames`, result processing at `0x81E370`, conversion at
`0x820CA0`): the second list is the host name (stored as owning player name); from the FIRST station
URL of each `GatheringURLs` the game takes address, port and `RVCID`, then probes the host and drops
the result if the probe cannot start or gets no answer. StationURL keys known to the game: `sid`,
`PID`, `CID`, `type`, `XLSPID`, `RVCID`. The server therefore returns the public URL first and adds
`PID` and `RVCID` (connection id from `Register`) to every host URL, and to the `Register` reply.

With RVCID present, the joining game sends 14-byte probes from its game port 7777 to the host's
port 9103 (`44 00`, `u32` own RVCID, 8 more bytes) and calls NATTraversal (`0x03`) method 3
`RequestProbeInitiationExt(["udp:/address=<host>;port=9103;RVCID=<host cid>"], "")`. The host does
not answer the probes on its own, so the server answers the call and invokes NATTraversal method 2
`InitiateProbe("udp:/address=<joiner>;port=<joiner port>;RVCID=<joiner cid>")` on the host.

The host accepts `InitiateProbe` and both games then probe each other, but always FROM their game
socket (7777) TO the peer's Quazal port (9103), and nobody answers: probes are handled on the game
socket. The NAT echo probes exist to tell the server the public endpoint of that game socket, so the
server now records it per IP and uses it as the first host URL and in `InitiateProbe`.

With game-port URLs the probes are answered both ways (`44 00 <rvcid> <token> <seq>` request,
`44 01 <rvcid> <token> <seq>` reply), yet the joiner still creates its own match. TurokGathering in
memory (reader `0x8257C0`): `+28 u32, +2C u32, +30 bool, +31 u8, +32 category, +33 mode, +34 large,
+35 u8`. `0x820CA0` turns `+31` into the number of OPEN connections (public or private depending on
`+30`). Hosts register with `+31 = 0`, i.e. every match looked full, so the server now sets it to
`max players - 1`.

**Two-PC matchmaking works (2026-10-27):** with CUSTOM MATCH both PCs see each other in the lobby
and the pre-match countdown starts with an automatically chosen map and mode. Join flow:
search (6) -> NAT traversal (3 / InitiateProbe) -> probes on port 7777 -> Turok method 5
`u32 gathering id + u8` = join; method 2 on someone else's gathering = leave. The host keeps
re-registering its gathering while in the lobby, so the server counts joined players per host and
derives open slots from them; full matches are left out of searches.

**A full match was played between the two PCs (2026-10-27).** During the match the host calls
MatchMaking (`0x15`) method 30 `SetState(u32 gathering id, u32 state)`: state 2 when the match starts,
6 when the match ends (natural end after ~10 minutes, or the host quitting). The client reads a `bool`
back (reader `0xA95ED0`); the server stores the state and answers true. After state 6 the host
unregisters its gathering, the other player leaves it (method 2) and both disconnect from the online
service. No stats or leaderboard calls appeared, even after a match played to its natural end; Turok
methods 10-12 are probably used by the leaderboards screens.

Not verified yet: QUICK MATCH with two players,
three or more players, players behind different NATs on the internet, Turok methods 3, 4, 7, 8,
10-12 (likely leaderboards/stats).

`tools/Disasm` (needs `Iced.dll` from NuGet, not committed) disassembles functions of the unpacked image.

`tools/DdlDump` reads the running game's memory (the exe is packed on disk), looks for DDL blobs and
saves the unpacked main module image for string analysis.

## Step 2: TurokServer

`src/TurokServer` is the emulator itself (C# 5, builds with the compiler bundled with Windows):

- Authentication server on UDP 30720: `Login`, `LoginEx`, `RequestTicket`, Kerberos tickets.
- Secure server on UDP 30721: ticket check in CONNECT, `Register` / `RegisterEx`.
- Any other call is logged with its parameters and answered with `Core::NotImplemented`.

```
src\TurokServer\build.bat
src\TurokServer\bin\TurokServer.exe
```

Logs go to `src\TurokServer\bin\logs`. Optional `server.ini` next to the exe overrides settings
(for example `PublicAddress=192.168.1.10`). `src\TestClient` is an end-to-end test that replays
the client handshake seen in the captures.

## Hosting on a VPS

Only the matchmaking runs on the server; matches are peer-to-peer between the players (UE3 on
UDP 7777), so the VPS needs little CPU and bandwidth.

1. Build `src\TurokServer\build.bat` on Windows and copy `TurokServer.exe` to the VPS.
2. Copy `tools/deploy/server.ini.example` next to it as `server.ini` and set `PublicAddress` to the
   VPS public IPv4 (or a DNS name). Keep `LogPackets=false` in production.
3. Open UDP 30720 and 30721 in the provider's firewall (security group) and on the machine.
4. Run it as a service:
   - Windows VPS: copy `tools/deploy/install-windows-task.bat` next to the exe and run it (firewall
     rule + scheduled task at boot, restarted on failure).
   - Linux VPS: `tools/deploy/turokserver.service` (Mono + systemd), instructions inside the file.
5. Back up `accounts.txt` (accounts are lost without it); logs rotate by themselves in `logs/`.

Internet-related behaviour of the server:

- The public endpoint of each player's game socket is learned from the NAT echo and stored per
  connection (players behind the same router no longer overwrite each other).
- Players sharing a public IP get each other's LAN address (best match with their own station
  URLs) and `GamePort` (7777) as first URL, since many routers cannot loop back to their own IP.
- Per-IP connection limit (`MaxConnectionsPerIp`), oversized datagrams dropped (`MaxDatagramSize`),
  reconnections from the same endpoint close the previous session cleanly.
- Not implemented: NAT relay (`NATTraversalRelay`). Two players both behind symmetric NATs may be
  unable to connect to each other.

## For players

1. Turok PC (2008) with the multiplayer working on LAN.
2. Redirect the Rendez-Vous host name to the server, from an administrator prompt:
   `tools\RedirectHosts.bat <server IPv4>` (adds `<ip> turokpclive.quazal.net` to the hosts file;
   `RedirectHosts.bat remove` undoes it). The hosts file only accepts IP addresses.
3. In Turok: PROFILE, create a profile, ONLINE ACCOUNT, CREATE ACCOUNT.
4. MULTIPLAYER, PUBLIC MATCH, QUICK MATCH or CUSTOM MATCH.
5. If matches never connect, allow inbound UDP 7777 for the game (or forward it on the router of
   whoever hosts).

## Step 1: PacketProbe

`tools/PacketProbe` listens on the Rendez-Vous ports, decodes PRUDP v0 packets, answers the
connection handshake and prints the first RMC requests sent by the game.

```
tools\PacketProbe\build.bat
tools\PacketProbe\PacketProbe.exe
```

Then start the game and open MULTIPLAYER > PUBLIC MATCH > QUICK MATCH.
Logs are written to `tools\PacketProbe\logs`.

## Diagnostic helpers

- `tools\RunTurokWithLog.bat` starts the game with Unreal Engine 3 logging
  (`Turok\TurokGame\Logs\TurokDebug.log`). Online log channels are unsuppressed in `TurokEngine.ini`.
- `tools\CaptureUdp.bat` captures all non-loopback UDP traffic, DNS included, with the built-in
  `pktmon` tool. It asks for administrator rights and saves to `tools\capture`.
