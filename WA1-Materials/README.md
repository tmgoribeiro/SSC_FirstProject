# 3S – Secure Streaming Solution (Work Assignment 1)

Computer Systems Security (SSC), MEI – FCT NOVA · Group 79449 / 72966

Secure Proxy and Secure Stream Server built on top of the provided insecure
`ProxySocketServer` / `OriginSocketServer`. The original HTTP request between the
proxy and the server is replaced by the **Secure Streaming Protocol** of the
assignment (§2.2):

* **Handshake** – Type 1 `SEQX ‖ PCC` (clear), Type 2 `E(SEQX+1 ‖ SRV ‖ CCC)`,
  Type 3 `E(SEQX+2 ‖ SHA-256(SRV) ‖ MEDIA)`.
* **Stream** – every media block is a Type 4 message `SEQB ‖ E(block)`; the end of
  the stream is a Type 5 message `SEQF ‖ E(SEQF ‖ "END" ‖ random)`.
* **Alerts** – any protocol violation is notified with a Type 255 message.

The cryptographic configuration (algorithm, mode, IV size, padding, MAC and keys)
is read from XML configuration files and can be changed **without recompiling**.
All commands below were tested on Windows 11 and Linux with Java 21/23.

---

## 1. Requirements

| Requirement | Notes |
|---|---|
| Java JDK **17 or newer** | uses `HexFormat`, text blocks and `switch ->`; tested with 21 and 23 |
| `lib/bcprov-jdk18on-1.86.jar` | Bouncy Castle provider (the jar of Lab 3.1), **included**. Only needed for RC6, AES/CCM and AES-CMAC |
| A web browser | Chrome / Edge / Firefox, to play the video |
| `curl` (optional) | for the command-line tests (included in Windows 10/11 as `curl.exe`) |

No other external libraries are used.

## 2. Project structure

```
WA1-Materials/                  <- project root: run every command from here
├── common/                     shared code (protocol, crypto, configuration)
│   ├── CryptoConfig.java         reads and validates the XML configuration files
│   ├── CryptoSuite.java          encrypt/decrypt: AEAD or Encrypt-then-MAC, fresh nonce per message
│   ├── SecureChannel.java        Header ‖ Payload messages, sequence numbers, AAD, alerts
│   ├── Handshake.java            handshake messages Type 1, 2, 3
│   ├── SecureOutputStream.java   server side: blocks -> Type 4, close() -> Type 5 (END)
│   ├── SecureInputStream.java    proxy side: decrypts/verifies Type 4, ends only on a valid Type 5
│   └── Protocol.java, Message.java, Utils.java, *Exception.java
├── streamserver/               Secure Stream Server
│   ├── OriginSocketServer.java   provided code + lines marked // WA1
│   ├── sservercrypto.config      default server configuration (AES/GCM)
│   └── media/                    movies (dante.mp4, ...)
├── streamproxy/                Secure Proxy
│   ├── ProxySocketServer.java    provided code + lines marked // WA1
│   ├── ProxyMetrics.java         instrumentation metrics (assignment §4)
│   └── proxycrypto.config        default proxy configuration (AES/GCM)
├── examples/                   more configurations (valid and INVALIDO-*)
├── tools/                      key generation and test tools (see §7)
├── results/                    outputs of the tests reported in the report
└── lib/bcprov-jdk18on-1.86.jar Bouncy Castle
```

Every change to the provided code is marked with `// WA1`.

## 3. Compile

**Linux / macOS (bash)**
```bash
javac -cp lib/bcprov-jdk18on-1.86.jar -d streamserver/out common/*.java streamserver/*.java
javac -cp lib/bcprov-jdk18on-1.86.jar -d streamproxy/out  common/*.java streamproxy/*.java
javac -cp lib/bcprov-jdk18on-1.86.jar -d tools/out        common/*.java tools/*.java
```

**Windows (PowerShell)** – the same commands with `\` paths:
```powershell
javac -cp lib\bcprov-jdk18on-1.86.jar -d streamserver/out common/*.java streamserver/*.java
javac -cp lib\bcprov-jdk18on-1.86.jar -d streamproxy/out  common/*.java streamproxy/*.java
javac -cp lib\bcprov-jdk18on-1.86.jar -d tools/out        common/*.java tools/*.java
```

## 4. Run (quick verification, one machine)

Open two terminals in the project root.

**Terminal 1 – Secure Stream Server** (`port mediaDir config`)
```bash
# Linux / macOS
java -cp streamserver/out:lib/bcprov-jdk18on-1.86.jar OriginSocketServer 8081 streamserver/media streamserver/sservercrypto.config
```
```powershell
# Windows: classpath separator is ';' and the classpath must be quoted
java -cp "streamserver/out;lib/bcprov-jdk18on-1.86.jar" OriginSocketServer 8081 streamserver/media streamserver/sservercrypto.config
```
Expected:
```
Origin server on http://localhost:8081/media/<file.mp4>  (dir: .../streamserver/media)
Secure Stream Server: AES/GCM/96/NoPadding
```

**Terminal 2 – Secure Proxy** (`port originHost originPort config`)
```bash
# Linux / macOS
java -cp streamproxy/out:lib/bcprov-jdk18on-1.86.jar ProxySocketServer 8080 localhost 8081 streamproxy/proxycrypto.config
```
```powershell
# Windows
java -cp "streamproxy/out;lib/bcprov-jdk18on-1.86.jar" ProxySocketServer 8080 localhost 8081 streamproxy/proxycrypto.config
```
Expected:
```
Proxy on http://localhost:8080/  ->  http://localhost:8081
Secure Proxy: AES/GCM/96/NoPadding
Pause between blocks: 0 ms
```

**Browser** – open <http://localhost:8080/>, write `dante.mp4` in the *File* box and
press **Load**. The video plays and seeking works. After each request the proxy
prints its metrics (§4 of the assignment), for example for a full download:

```
[metrics] dante.mp4  HTTP 200  COMPLETE (END verified)
   encrypted blocks received : 25335
   decrypted blocks forwarded: 25334
   media bytes forwarded     : 25941346  (asked 25941346, original file 25941346)
   bytes received (network)  : 27081717
   throughput                : ... kB/s  (25941346 bytes in ... s)
```

`INCOMPLETE (... connection ... aborted / Broken pipe)` lines are normal: they are
Range requests that the browser cancels itself (to seek or because it has enough
data). Only `ERROR ...` lines mean a protocol or security failure.

**Command-line check that the movie arrives unchanged**
```bash
curl -s -o received.mp4 http://localhost:8080/video/dante.mp4
cmp received.mp4 streamserver/media/dante.mp4 && echo IDENTICAL
```
```powershell
curl.exe -s -o $env:TEMP\r.mp4 http://localhost:8080/video/dante.mp4
(Get-FileHash $env:TEMP\r.mp4).Hash -eq (Get-FileHash streamserver\media\dante.mp4).Hash   # True
```

## 5. Cryptographic configurations

The proxy and the server must use **the same configuration file** (same algorithms
**and** same keys). To change the configuration, give another file as the last
argument of both programs – **no recompilation**:

```bash
java -cp streamserver/out:lib/bcprov-jdk18on-1.86.jar OriginSocketServer 8081 streamserver/media examples/chacha20-poly1305.config
java -cp streamproxy/out:lib/bcprov-jdk18on-1.86.jar  ProxySocketServer 8080 localhost 8081 examples/chacha20-poly1305.config
```

| File | Proposal (PCC) | Construction | Provider |
|---|---|---|---|
| `streamserver/sservercrypto.config`, `streamproxy/proxycrypto.config` | AES/GCM/96/NoPadding | AEAD | SunJCE |
| `examples/chacha20-poly1305.config` | ChaCha20/Poly1305/96/NULL | AEAD | SunJCE |
| `examples/aes-ccm.config` | AES/CCM/96/NoPadding | AEAD (128-bit tag) | Bouncy Castle |
| `examples/aes-ctr-hmac.config` | AES/CTR/128/NoPadding + HMAC-SHA256 | Encrypt-then-MAC | SunJCE |
| `examples/aes-ctr-cmac.config` | AES/CTR/128/NoPadding + AES-CMAC | Encrypt-then-MAC | SunJCE + BC |
| `examples/aes-cbc-hmac512.config` | AES/CBC/128/PKCS5Padding + HMAC-SHA-512 | Encrypt-then-MAC | SunJCE |
| `examples/rc6-cbc-hmac.config` | RC6/CBC/128/PKCS5Padding + HMAC-SHA256 | Encrypt-then-MAC | Bouncy Castle |
| `examples/chacha20-hmac.config` | ChaCha20/NULL/96/NULL + HMAC-SHA256 | Encrypt-then-MAC | SunJCE |
| `examples/aes-gcm-outra-chave.config` | AES/GCM/96/NoPadding | same as default, **other key** (test of a wrong key) | SunJCE |

Configurations that are **refused at start-up** (the program stops with a `CryptoException`):

| File | Reason |
|---|---|
| `examples/INVALIDO-ecb.config` | ECB mode is not allowed |
| `examples/INVALIDO-cbc-sem-mac.config` | CBC without a MAC gives no integrity |
| `examples/INVALIDO-mesma-chave.config` | MAC key equal to the encryption key |
| `examples/INVALIDO-keysize-errado.config` | key length different from `<Keysize>` |
| `examples/INVALIDO-chacha20-chave128.config` | ChaCha20 needs a 256-bit key |

New keys can be generated with `tools/GenerateKey` (§7). Keys may be written in
hexadecimal or Base64. The XML tags are read case-insensitively, so both the
`<MACsuite>` and `<MACSuite>` spellings used in the assignment are accepted.

## 6. Running on different physical machines

The protocol runs over TCP, so the proxy and the server can be on different hosts:

1. Copy the project (or at least `common/`, the component folder, `lib/` and the
   configuration file) to both machines and compile there (§3).
2. **Server machine** (for example `192.168.1.20`): start the server as in §4 and
   allow incoming TCP connections on port **8081** in its firewall.
3. **Proxy machine**: start the proxy with the server's address as `originHost`:
   ```bash
   java -cp streamproxy/out:lib/bcprov-jdk18on-1.86.jar ProxySocketServer 8080 192.168.1.20 8081 streamproxy/proxycrypto.config
   ```
4. On the proxy machine open <http://localhost:8080/>.

Both machines must use configuration files with the same algorithms and keys
(for example copy `streamserver/sservercrypto.config` and use it for the proxy too).

## 7. Tools and tests

All tools run from the project root with the classpath `tools/out` + the jar
(on Windows use `"tools/out;lib/bcprov-jdk18on-1.86.jar"`). Saved outputs of every
test are in `results/`.

| Tool | Command | Expected result |
|---|---|---|
| Key generation | `java -cp tools/out:lib/bcprov-jdk18on-1.86.jar GenerateKey AES 256` | a random key in hex and Base64 |
| Configuration check | `java -cp tools/out:lib/bcprov-jdk18on-1.86.jar ConfigTest examples/*.config` (PowerShell: `... ConfigTest (Get-ChildItem examples\*.config).FullName`) | `VALID` for the 8 valid files, `REFUSED: <reason>` for the 5 `INVALIDO-*` |
| Crypto layer | `java -cp tools/out:lib/bcprov-jdk18on-1.86.jar CryptoSuiteTest examples/aes-ccm.config` | round-trip, fresh nonce, tampering rejected, overhead per 1 KB, `ALL TESTS PASSED` |
| Protocol messages | `java -cp tools/out:lib/bcprov-jdk18on-1.86.jar ChannelTest examples/aes-ctr-hmac.config` | replay, reorder, drop, type 4→5, bit flip, wrong version... all detected, `ALL TESTS PASSED` |
| Handshake + MITM | `java -cp tools/out:lib/bcprov-jdk18on-1.86.jar HandshakeTest examples/aes-ccm.config examples/aes-ccm.config streamproxy/proxycrypto.config` | 7 tests (normal, incompatible config, wrong key, changed PCC, changed SEQX, replay, wrong order), `ALL TESTS PASSED` |

### 7.1 Man-in-the-middle on the real stream (`StreamMallory`)

Mallory sits between the proxy and the server and attacks block 50 of the stream.

```bash
# 1. server (as in §4), port 8081
# 2. Mallory, port 8082 -> server 8081, with one attack:
java -cp tools/out:lib/bcprov-jdk18on-1.86.jar StreamMallory 8082 localhost 8081 flip
# 3. proxy connected to Mallory (originPort 8082):
java -cp streamproxy/out:lib/bcprov-jdk18on-1.86.jar ProxySocketServer 8080 localhost 8082 streamproxy/proxycrypto.config
# 4. request
curl -s -o /dev/null http://localhost:8080/video/dante.mp4
```

| Attack | Threat | Proxy metrics |
|---|---|---|
| `none` | – | `COMPLETE (END verified)` |
| `eavesdrop` | eavesdropping | `COMPLETE`; Mallory finds **nothing** in clear (movie name, HTTP headers, MP4 signature) |
| `flip` | modification | `ERROR INTEGRITY_FAILURE` |
| `drop` | deletion | `ERROR BAD_SEQUENCE ... (reordered or missing message)` |
| `dup` | replay | `ERROR BAD_SEQUENCE ... (replayed or duplicated message)` |
| `swap` | reordering | `ERROR BAD_SEQUENCE ... (reordered or missing message)` |
| `type` | change of the clear header (Type 4 → 5) | `ERROR INTEGRITY_FAILURE` |
| `inject` | forged block | `ERROR INTEGRITY_FAILURE` |
| `cut` | truncation (END removed) | `INCOMPLETE` – the stream is not accepted as complete |

### 7.2 Concurrent sessions (`ConcurrencyTest`)

Start one server and three proxies (ports 8080, 8090, 8091, same configuration), then:
```bash
java -cp tools/out:lib/bcprov-jdk18on-1.86.jar ConcurrencyTest streamserver/media 8080:dante.mp4 8090:sintel.mp4 8091:caminandes.mp4
```
The same downloads run one after the other and then all at the same time; each
movie is compared with the original (SHA-256). Expected: `hash OK` for every client
and `ALL 3 CONCURRENT STREAMS OK`. Any movies present in `streamserver/media` can
be used (at least two different ones).

### 7.3 Playout pacing (optimisation, `ProxySocketServer` options)

Optional Java system properties of the proxy (default: no pause, as the original code):

| Option | Meaning |
|---|---|
| `-Ddelay=<ms>` | fixed pause before each 1024-byte block (the original `Thread.sleep`) |
| `-Drate=<kB/s>` | send at this average rate (1 kB = 1000 bytes) |
| `-Dburst=<kB>` | with `-Drate`: the first kB of each request are sent at full speed (fast start) |

Example – the movie's bitrate (225.6 kB/s for `dante.mp4`) + 10 %, with a 2 MB burst:
```bash
java -Drate=250 -Dburst=2000 -cp streamproxy/out:lib/bcprov-jdk18on-1.86.jar ProxySocketServer 8080 localhost 8081 streamproxy/proxycrypto.config
```
(on Windows PowerShell write the options quoted: `"-Drate=250" "-Dburst=2000"`).

## 8. Movies

| File | Size | Duration | Included |
|---|---|---|---|
| `dante.mp4` | 25.9 MB | 1 min 55 s | yes (provided with the assignment) |
| `sintel.mp4` | 7.6 MB | 52 s | Sintel trailer 480p, Blender Foundation (CC BY) – <https://durian.blender.org/download/> |
| `caminandes.mp4` | 126 MB | 2 min 26 s | optional – *Caminandes: Gran Dillama*, Blender Foundation (CC BY), `caminandes_gran_dillama.mp4.zip` from <https://cdimage.debian.org/mirror/blender.org/demo/movies> |

Any MP4 file that the browser can play can be added to `streamserver/media/`
(use a file name without spaces).