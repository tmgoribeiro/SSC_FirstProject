import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Tests the handshake over real sockets, with a Mallory relay that changes, replays or reorders messages
 *
 * Use: java HandshakeTest <proxy config> <server config> <other config>
 */
public class HandshakeTest
{
    static ExecutorService pool = Executors.newCachedThreadPool();
    static int failures = 0;

    /**
     * Run the 7 handshake tests
     *
     * @param args : proxy config, server config (same as the proxy) and a different config
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length != 3)
        {
            System.out.println("Use: java HandshakeTest <proxy config> <server config> <other config>");
            System.exit(-1);
        }
        CryptoConfig proxyCfg = CryptoConfig.load(args[0]);
        CryptoConfig serverCfg = CryptoConfig.load(args[1]);
        CryptoConfig otherCfg = CryptoConfig.load(args[2]);
        CryptoConfig wrongKeyCfg = CryptoConfig.load(args[1]);
        new SecureRandom().nextBytes(wrongKeyCfg.symKey);           // same algorithms, other keys
        if (wrongKeyCfg.macKey != null) new SecureRandom().nextBytes(wrongKeyCfg.macKey);

        System.out.println("Proxy  config: " + proxyCfg.proposal());
        System.out.println("Server config: " + serverCfg.proposal());
        System.out.println();

        // 1. normal handshake (through Mallory, who only records)
        List<byte[]> recorded = new ArrayList<>();
        test("1. normal handshake", proxyCfg, serverCfg, (i, m) -> { recorded.add(m.clone()); return m; },
             true, "OK", "OK");

        // 2. incompatible proposal
        test("2. incompatible config (proxy " + otherCfg.proposal() + ")", otherCfg, serverCfg, null,
             false, "received alert CONFIG_REJECTED", "CONFIG_REJECTED");

        // 3. same configuration, different key
        test("3. same configuration, wrong key", proxyCfg, wrongKeyCfg, null,
             false, "INTEGRITY_FAILURE", "received alert INTEGRITY_FAILURE");

        // 4. Mallory changes the proposal (PCC) in message 1 (it goes in clear)
        test("4. Mallory changes the PCC in message 1", proxyCfg, serverCfg,
             (i, m) -> { if (i == 0) m[m.length - 1] ^= 0x01; return m; },
             false, "received alert CONFIG_REJECTED", "CONFIG_REJECTED");

        // 5. Mallory changes SEQX in message 1 (it goes in clear)
        test("5. Mallory changes SEQX in message 1", proxyCfg, serverCfg,
             (i, m) -> { if (i == 0) m[Protocol.HEADER_SIZE + 7] ^= 0x01; return m; },
             false, "BAD_SEQUENCE", "received alert BAD_SEQUENCE");

        // 6. Mallory replays the recorded messages 1 and 3 of test 1 to the server
        replayTest("6. Mallory replays old messages 1 and 3", serverCfg, recorded);

        // 7. Mallory sends message 3 before message 1
        outOfOrderTest("7. Mallory sends message 3 first", serverCfg, recorded);

        System.out.println("======================================");
        System.out.println(failures == 0 ? "ALL TESTS PASSED" : failures + " TEST(S) FAILED");
        pool.shutdownNow();
        System.exit(failures == 0 ? 0 : 1);
    }

    // Proxy and Server

    /**
     * Server side: accept one connection and run the server handshake
     *
     * @param ss : server socket
     * @param cfg : server configuration
     * @return result : "OK ..." or the error seen by the server
     */
    static String serverSide(ServerSocket ss, CryptoConfig cfg)
    {
        try (Socket s = ss.accept())
        {
            SecureChannel ch = new SecureChannel(s.getInputStream(), s.getOutputStream(), new CryptoSuite(cfg));
            try
            {
                Handshake.Result r = Handshake.server(ch, cfg);
                return "OK (movie " + r.media + ", first block SEQ " + r.firstBlockSeq + ")";
            }
            catch (ProtocolException e)
            {
                ch.sendAlert(e.alert, e.getMessage());          // notify the other side
                return e.getMessage() + " -> alert sent";
            }
        }
        catch (AlertException e)
        {
            return e.getMessage();
        }
        catch (Exception e)
        {
            return "connection closed (" + e.getClass().getSimpleName() + ")";
        }
    }

    /**
     * Proxy side: connect and run the proxy handshake for "dante.mp4"
     *
     * @param port : port to connect to (server or Mallory)
     * @param cfg : proxy configuration
     * @return result : "OK ..." or the error seen by the proxy
     */
    static String proxySide(int port, CryptoConfig cfg)
    {
        try (Socket s = new Socket("localhost", port))
        {
            SecureChannel ch = new SecureChannel(s.getInputStream(), s.getOutputStream(), new CryptoSuite(cfg));
            try
            {
                Handshake.Result r = Handshake.proxy(ch, cfg, "dante.mp4");
                return "OK (first block SEQ " + r.firstBlockSeq + ")";
            }
            catch (ProtocolException e)
            {
                ch.sendAlert(e.alert, e.getMessage());
                return e.getMessage() + " -> alert sent";
            }
        }
        catch (AlertException e)
        {
            return e.getMessage();
        }
        catch (Exception e)
        {
            return "connection closed (" + e.getClass().getSimpleName() + ")";
        }
    }

    // Tests

    /** What Mallory does to each message sent by the proxy */
    interface Tamper { byte[] apply(int index, byte[] message); }

    /**
     * Run one handshake between proxy and server, optionally through Mallory
     *
     * @param name : test name
     * @param proxyCfg : proxy configuration
     * @param serverCfg : server configuration
     * @param mallory : change applied to the proxy messages, or null (direct connection)
     * @param mustSucceed : true if the handshake must succeed
     * @param proxyExpect : text expected in the proxy result
     * @param serverExpect : text expected in the server result
     */
    static void test(String name, CryptoConfig proxyCfg, CryptoConfig serverCfg, Tamper mallory,
                     boolean mustSucceed, String proxyExpect, String serverExpect) throws Exception
    {
        try (ServerSocket server = new ServerSocket(0); ServerSocket relay = new ServerSocket(0))
        {
            Future<String> srv = pool.submit(() -> serverSide(server, serverCfg));
            int port = server.getLocalPort();
            if (mallory != null)
            {
                pool.submit(() -> relay(relay, server.getLocalPort(), mallory));
                port = relay.getLocalPort();
            }
            final int p = port;
            Future<String> prx = pool.submit(() -> proxySide(p, proxyCfg));
            String pr = prx.get(10, TimeUnit.SECONDS), sr = srv.get(10, TimeUnit.SECONDS);
            boolean ok = pr.contains(proxyExpect) && sr.contains(serverExpect)
                         && (mustSucceed == (pr.startsWith("OK") && sr.startsWith("OK")));
            report(name, ok, pr, sr);
        }
    }

    /**
     * Mallory replays the old messages 1 and 3 to a new server session
     *
     * @param name : test name
     * @param serverCfg : server configuration
     * @param recorded : messages recorded in test 1
     */
    static void replayTest(String name, CryptoConfig serverCfg, List<byte[]> recorded) throws Exception
    {
        try (ServerSocket server = new ServerSocket(0))
        {
            Future<String> srv = pool.submit(() -> serverSide(server, serverCfg));
            try (Socket s = new Socket("localhost", server.getLocalPort()))
            {
                OutputStream out = s.getOutputStream();
                out.write(recorded.get(0));                         // old message 1
                out.flush();
                readMessage(new DataInputStream(s.getInputStream())); // new message 2 (new SRV)
                out.write(recorded.get(1));                         // old message 3 (old R)
                out.flush();
                String sr = srv.get(10, TimeUnit.SECONDS);
                report(name, sr.contains("BAD_CHALLENGE"), "(Mallory)", sr);
            }
        }
    }

    /**
     * Mallory sends message 3 as the first message
     *
     * @param name : test name
     * @param serverCfg : server configuration
     * @param recorded : messages recorded in test 1
     */
    static void outOfOrderTest(String name, CryptoConfig serverCfg, List<byte[]> recorded) throws Exception
    {
        try (ServerSocket server = new ServerSocket(0))
        {
            Future<String> srv = pool.submit(() -> serverSide(server, serverCfg));
            try (Socket s = new Socket("localhost", server.getLocalPort()))
            {
                s.getOutputStream().write(recorded.get(1));          // message 3 first
                s.getOutputStream().flush();
                String sr = srv.get(10, TimeUnit.SECONDS);
                report(name, sr.contains("UNEXPECTED_MESSAGE"), "(Mallory)", sr);
            }
        }
    }

    /**
     * Print the result of one test
     *
     * @param name : test name
     * @param ok : true if the test passed
     * @param proxyResult : what the proxy saw
     * @param serverResult : what the server saw
     */
    static void report(String name, boolean ok, String proxyResult, String serverResult)
    {
        System.out.println((ok ? "OK   " : "FAIL ") + name);
        System.out.println("       proxy : " + proxyResult);
        System.out.println("       server: " + serverResult);
        if (!ok) failures++;
    }

    // Mallory (relay)

    /**
     * Relay proxy -> server message by message (applying Mallory's change), server -> proxy as is
     *
     * @param relay : socket where Mallory waits for the proxy
     * @param serverPort : port of the server
     * @param mallory : change applied to each proxy message
     */
    static void relay(ServerSocket relay, int serverPort, Tamper mallory)
    {
        try (Socket fromProxy = relay.accept(); Socket toServer = new Socket("localhost", serverPort))
        {
            pool.submit(() -> copy(toServer.getInputStream(), fromProxy.getOutputStream()));
            DataInputStream in = new DataInputStream(fromProxy.getInputStream());
            DataOutputStream out = new DataOutputStream(toServer.getOutputStream());
            for (int i = 0; ; i++)
            {
                byte[] m = readMessage(in);
                out.write(mallory.apply(i, m));
                out.flush();
            }
        }
        catch (IOException e)
        {
            // one side closed: end of the relay
        }
    }

    /**
     * Copy all bytes from one stream to another
     *
     * @param in : source stream
     * @param out : destination stream
     * @return null : (for use as a task)
     */
    static Void copy(InputStream in, OutputStream out) throws IOException
    {
        byte[] buf = new byte[4096];
        int n;
        try
        {
            while ((n = in.read(buf)) != -1) { out.write(buf, 0, n); out.flush(); }
        }
        catch (IOException e) { /* closed */ }
        return null;
    }

    /**
     * Read one whole message (Header || Payload) as bytes
     *
     * @param in : stream to read from
     * @return message : header and payload
     */
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