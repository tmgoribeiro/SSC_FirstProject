import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * The "sender" writes a small session into a buffer 
 * 
 * 
 * Mallory changes the list of messages; the "receiver" reads them and must
 * accept the normal session and REJECT every attack.
 *
 */
public class ChannelTest
{
    static CryptoConfig cfg;
    static long seqX;

    public static void main(String[] args) throws Exception
    {
        if (args.length != 1)
        {
            System.out.println("Use: java ChannelTest <config file>");
            System.exit(-1);
        }
        cfg = CryptoConfig.load(args[0]);
        System.out.println("Config: " + cfg.proposal() + (cfg.macAlgorithm != null ? " + " + cfg.macAlgorithm : ""));
        seqX = new SecureRandom().nextLong() & Long.MAX_VALUE;   // random initial SEQ

        List<byte[]> session = recordSession(seqX);
        List<byte[]> other = recordSession(seqX + 1000);    
        int failures = 0;
        failures += run("normal session                     ", session, true);
        failures += run("replay block 1 (sent twice)         ", list(session, 0, 1, 1, 2, 3, 4), false);
        failures += run("reorder blocks 1 and 2              ", list(session, 0, 2, 1, 3, 4), false);
        failures += run("drop block 2                        ", list(session, 0, 1, 3, 4), false);
        failures += run("drop the end-of-stream (type 5)     ", list(session, 0, 1, 2, 3), false);
        failures += run("drop block 2 + fix the clear SEQs   ", fixSeqs(list(session, 0, 1, 3, 4)), false);
        failures += run("block 3 turned into type 5 (END)    ", changeType(session, 3, Protocol.TYPE_5), false);
        failures += run("flip 1 bit of block 1 ciphertext    ", flipBit(session, 1, Protocol.HEADER_SIZE + 8 + 20), false);
        failures += run("header version 1:1 -> 1:2           ", changeRelease(session, 1, 2), false);
        failures += run("forged huge payload size            ", hugeSize(session, 1), false);
        failures += run("block injected from an old session  ", list2(session, other, 1), false);
        failures += run("connection cut in the middle        ", truncate(session, 2, 10), false);

        System.out.println("======================================");
        System.out.println(failures == 0 ? "ALL TESTS PASSED" : failures + " TEST(S) FAILED");
    }


    /** The sender writes the messages into a buffer; returns them one by one. */
    static List<byte[]> recordSession(long seqX) throws Exception
    {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        SecureChannel sender = new SecureChannel(new ByteArrayInputStream(new byte[0]), wire, new CryptoSuite(cfg));
        sender.sendSeqInside(Protocol.TYPE_2, seqX + 1, "hello".getBytes());
        sender.sendSeqClear(Protocol.TYPE_4, seqX + 2, "block one ".getBytes());
        sender.sendSeqClear(Protocol.TYPE_4, seqX + 3, "block two ".getBytes());
        sender.sendSeqClear(Protocol.TYPE_4, seqX + 4, "block three".getBytes());
        sender.sendSeqClear(Protocol.TYPE_5, seqX + 5, "END".getBytes());
        return split(wire.toByteArray());
    }

    /** The receiver: what the Proxy will do. Returns null if accepted, else the reason. */
    static String receive(List<byte[]> messages)
    {
        ByteArrayOutputStream ignore = new ByteArrayOutputStream();
        SecureChannel receiver = new SecureChannel(new ByteArrayInputStream(join(messages)), ignore, new CryptoSuite(cfg));
        try
        {
            receiver.openSeqInside(receiver.receive(Protocol.TYPE_2), seqX + 1);
            long expected = seqX + 2;
            StringBuilder got = new StringBuilder();
            while (true)
            {
                Message m = receiver.receive();
                if (m.type == Protocol.TYPE_4)
                    got.append(new String(receiver.openSeqClear(m, expected++)));
                else if (m.type == Protocol.TYPE_5)
                {
                    receiver.openSeqClear(m, expected);
                    break;
                }
                else
                    throw new ProtocolException(Protocol.ALERT_UNEXPECTED_MESSAGE, "type " + m.type);
            }
            if (!got.toString().equals("block one block two block three"))
                return "WRONG CONTENT: " + got;
            return null;
        }
        catch (ProtocolException | AlertException e)
        {
            return e.getMessage();
        }
        catch (IOException e)
        {
            return "connection ended before the end of the stream (" + e.getClass().getSimpleName() + ")";
        }
    }

    static int run(String name, List<byte[]> messages, boolean mustAccept)
    {
        String result = receive(messages);
        boolean ok = mustAccept ? result == null : result != null;
        System.out.println((ok ? "OK   " : "FAIL ") + name + " -> "
                           + (result == null ? "ACCEPTED" : "REJECTED: " + result));
        return ok ? 0 : 1;
    }

    // Mallory



    static List<byte[]> list(List<byte[]> s, int... idx)
    {
        List<byte[]> r = new ArrayList<>();
        for (int i : idx) r.add(s.get(i).clone());
        return r;
    }

    /** session message 0, then message i of the OTHER session, then the rest. */
    static List<byte[]> list2(List<byte[]> s, List<byte[]> other, int i)
    {
        List<byte[]> r = list(s, 0);
        r.add(other.get(i).clone());
        for (int k = 1; k < s.size(); k++) r.add(s.get(k).clone());
        return r;
    }

    /** After dropping a block, Mallory rewrites the CLEAR SEQs so they look consecutive. */
    static List<byte[]> fixSeqs(List<byte[]> s)
    {
        long next = seqX + 2;
        for (int i = 1; i < s.size(); i++)
            writeLong(s.get(i), Protocol.HEADER_SIZE, next++);
        return s;
    }

    static List<byte[]> changeType(List<byte[]> s, int i, int newType)
    {
        List<byte[]> r = list(s, 0, 1, 2, 3, 4);
        r.get(i)[4] = (byte) newType;                    // header: version(2) release(2) TYPE(1)
        return r;
    }

    static List<byte[]> flipBit(List<byte[]> s, int i, int pos)
    {
        List<byte[]> r = list(s, 0, 1, 2, 3, 4);
        r.get(i)[pos] ^= 0x01;
        return r;
    }

    static List<byte[]> changeRelease(List<byte[]> s, int i, int release)
    {
        List<byte[]> r = list(s, 0, 1, 2, 3, 4);
        r.get(i)[2] = 0;
        r.get(i)[3] = (byte) release;                    // header: version(2) RELEASE(2)
        return r;
    }

    static List<byte[]> hugeSize(List<byte[]> s, int i)
    {
        List<byte[]> r = list(s, 0, 1, 2, 3, 4);
        writeInt(r.get(i), 5, 2_000_000_000);            // header: ... type(1) SIZE(4)
        return r;
    }

    static List<byte[]> truncate(List<byte[]> s, int i, int keep)
    {
        List<byte[]> r = list(s, 0, 1);
        byte[] cut = new byte[keep];
        System.arraycopy(s.get(i), 0, cut, 0, keep);
        r.add(cut);
        return r;
    }



    /** Split the bytes of the "network" into messages, using the header size field. */
    static List<byte[]> split(byte[] wire) throws IOException
    {
        List<byte[]> r = new ArrayList<>();
        DataInputStream d = new DataInputStream(new ByteArrayInputStream(wire));
        int pos = 0;
        while (pos < wire.length)
        {
            d.skipBytes(5);
            int size = d.readInt();
            byte[] m = new byte[Protocol.HEADER_SIZE + size];
            System.arraycopy(wire, pos, m, 0, m.length);
            d.skipBytes(size);
            r.add(m);
            pos += m.length;
        }
        return r;
    }

    static byte[] join(List<byte[]> l)
    {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] m : l) b.write(m, 0, m.length);
        return b.toByteArray();
    }

    static void writeLong(byte[] b, int off, long v)
    {
        for (int i = 7; i >= 0; i--) { b[off + i] = (byte) v; v >>>= 8; }
    }

    static void writeInt(byte[] b, int off, int v)
    {
        for (int i = 3; i >= 0; i--) { b[off + i] = (byte) v; v >>>= 8; }
    }
}