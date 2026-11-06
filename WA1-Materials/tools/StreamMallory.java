import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Mallory, a Man-in-the-Middle between the Secure Proxy and the Secure Stream Server
 * (WA1 threat model, section 3: "an attacker can eavesdrop on, modify, inject, replay,
 * reorder, or drop messages"). The proxy is started with originPort = Mallory's port:
 *
 *   Server :  java -cp out OriginSocketServer 8081 media
 *   Mallory:  java -cp tools/out StreamMallory 8082 localhost 8081 <attack>
 *   Proxy  :  java -cp out ProxySocketServer 8080 localhost 8082
 *
 * Server -> Proxy messages are relayed one by one (Header || Payload, as HandshakeTest);
 * the attack is applied to stream block number N (the N-th Type 4 message, default 50).
 * Attacks:
 *   none      only relays (the stream must arrive COMPLETE)
 *   eavesdrop only listens, and looks for plaintext in both directions: movie name,
 *             HTTP request/response, MP4 "ftyp" (also works against the insecure base code)
 *   flip      changes one byte of the encrypted block (as TamperingExample: ^= '0' ^ '9')
 *   drop      removes block N                      (missing block)
 *   dup       sends block N twice                  (replayed / duplicated block)
 *   swap      sends block N+1 before block N       (reordered blocks)
 *   type      changes Type 4 into Type 5 in the clear header (fake end of stream)
 *   inject    inserts a forged block (next SEQ, random "ciphertext")
 *   cut       removes the Type 5 END message       (truncated stream)
 */
public class StreamMallory
{
    static ExecutorService pool = Executors.newCachedThreadPool();   // as the base code

    public static void main(String[] args) throws Exception
    {
        if (args.length < 4)
        {
            System.out.println("Use: java StreamMallory <port> <serverHost> <serverPort> <attack> [N=50]");
            System.out.println("     attack: none | eavesdrop | flip | drop | dup | swap | type | inject | cut");
            System.exit(-1);
        }
        int port = Integer.parseInt(args[0]);
        String serverHost = args[1];
        int serverPort = Integer.parseInt(args[2]);
        String attack = args[3];
        int n = args.length > 4 ? Integer.parseInt(args[4]) : 50;

        try (ServerSocket server = new ServerSocket(port))
        {
            System.out.println("Mallory on " + port + " -> " + serverHost + ":" + serverPort + "  attack: " + attack
                               + (attack.equals("none") || attack.equals("eavesdrop") || attack.equals("cut") ? "" : " on block " + n));
            while (true)
            {
                Socket proxy = server.accept();
                pool.submit(() -> relay(proxy, serverHost, serverPort, attack, n));
            }
        }
    }

    static void relay(Socket proxy, String serverHost, int serverPort, String attack, int n)
    {
        try (proxy; Socket origin = new Socket(serverHost, serverPort))
        {
            ByteArrayOutputStream fromProxy = new ByteArrayOutputStream();     // what Mallory sees Proxy -> Server
            ByteArrayOutputStream fromServer = new ByteArrayOutputStream();    // what Mallory sees Server -> Proxy
            pool.submit(() -> copy(proxy.getInputStream(), origin.getOutputStream(), fromProxy));

            if (attack.equals("eavesdrop"))                 // only listens: works with any traffic, even plain HTTP
            {
                copy(origin.getInputStream(), proxy.getOutputStream(), fromServer);
                eavesdrop(fromProxy.toByteArray(), fromServer.toByteArray());
                return;
            }

            DataInputStream in = new DataInputStream(origin.getInputStream());
            OutputStream out = proxy.getOutputStream();
            int block = 0;                  // Type 4 messages seen
            byte[] held = null;             // for swap
            try
            {
                while (true)
                {
                    byte[] m = readMessage(in);
                    int type = m[4] & 0xff;

                    if (type == Protocol.TYPE_4)
                    {
                        block++;
                        if (block == n)
                        {
                            switch (attack)
                            {
                                case "flip" -> {
                                    m[m.length - 20] ^= '0' ^ '9';                 // as TamperingExample
                                    System.out.println("Mallory: changed one byte of block " + n);
                                }
                                case "drop" -> {
                                    System.out.println("Mallory: dropped block " + n);
                                    continue;
                                }
                                case "dup" -> {
                                    out.write(m);
                                    System.out.println("Mallory: sent block " + n + " twice");
                                }
                                case "swap" -> {
                                    held = m;
                                    System.out.println("Mallory: holding block " + n + " to send it after block " + (n + 1));
                                    continue;
                                }
                                case "type" -> {
                                    m[4] = (byte) Protocol.TYPE_5;
                                    System.out.println("Mallory: changed block " + n + " from Type 4 to Type 5");
                                }
                                case "inject" -> {
                                    byte[] fake = m.clone();
                                    new SecureRandom().nextBytes(fake);             // random "ciphertext"
                                    System.arraycopy(m, 0, fake, 0, Protocol.HEADER_SIZE + 8);   // same header and SEQ
                                    out.write(fake);
                                    System.out.println("Mallory: injected a forged block with SEQ of block " + n);
                                    continue;
                                }
                            }
                        }
                    }
                    if (type == Protocol.TYPE_5 && attack.equals("cut"))
                    {
                        System.out.println("Mallory: removed the END message (Type 5) after " + block + " blocks");
                        break;
                    }
                    out.write(m);
                    out.flush();
                    if (held != null && block == n + 1)
                    {
                        out.write(held);
                        out.flush();
                        held = null;
                    }
                }
            }
            catch (IOException e)
            {
                // one side closed the connection
            }
        }
        catch (IOException e)
        {
            System.out.println("Mallory: " + e.getMessage());
        }
    }

    /** Can Mallory read anything? (the insecure base code sends all of this in clear) */
    static void eavesdrop(byte[] fromProxy, byte[] fromServer)
    {
        System.out.println("Mallory listened to " + fromProxy.length + " bytes Proxy->Server and "
                           + fromServer.length + " bytes Server->Proxy (first 1 MB):");
        look("movie name \".mp4\"     (Proxy->Server)", fromProxy, ".mp4");
        look("request \"GET /media\"   (Proxy->Server)", fromProxy, "GET /media");
        look("response \"HTTP/1.1\"    (Server->Proxy)", fromServer, "HTTP/1.1");
        look("header \"Content-Length\" (Server->Proxy)", fromServer, "Content-Length");
        look("MP4 signature \"ftyp\"   (Server->Proxy)", fromServer, "ftyp");
    }

    static void look(String what, byte[] data, String text)
    {
        String s = new String(data, StandardCharsets.ISO_8859_1);
        System.out.println("   " + what + ": " + (s.contains(text) ? "FOUND (in clear!)" : "not found"));
    }

    static Void copy(InputStream in, OutputStream out, ByteArrayOutputStream seen)
    {
        byte[] buf = new byte[4096];
        int n;
        try
        {
            while ((n = in.read(buf)) != -1)
            {
                if (seen.size() < 1024 * 1024) seen.write(buf, 0, n);
                out.write(buf, 0, n);
                out.flush();
            }
        }
        catch (IOException e) { /* closed */ }
        return null;
    }

    /** Reads one whole message (Header || Payload) as bytes (as HandshakeTest). */
    static byte[] readMessage(DataInputStream in) throws IOException
    {
        byte[] header = new byte[Protocol.HEADER_SIZE];
        in.readFully(header);
        int size = ((header[5] & 0xff) << 24) | ((header[6] & 0xff) << 16) | ((header[7] & 0xff) << 8) | (header[8] & 0xff);
        byte[] m = new byte[Protocol.HEADER_SIZE + size];
        System.arraycopy(header, 0, m, 0, header.length);
        in.readFully(m, Protocol.HEADER_SIZE, size);
        return m;
    }
}