import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * The Stream Server writes the movie to this stream instead of the socket
 * (so the provided serveFile / writeHeaders stay unchanged):
 *   each write(...)  -> message Type 4:  SEQB || E( block )
 *   close()          -> message Type 5:  SEQF || E( SEQF || "END" || random string )
 * (WA1 2.2.3). SEQB starts at SEQZ + 1 (returned by the handshake).
 */
public class SecureOutputStream extends OutputStream
{
    private final SecureChannel ch;
    private long seq;

    public SecureOutputStream(SecureChannel ch, long firstBlockSeq)
    {
        this.ch = ch;
        this.seq = firstBlockSeq;
    }

    /** One block of serveFile (out.write(block, 0, n)) -> Type 4: SEQB || E( block ) */
    @Override
    public void write(byte[] b, int off, int len) throws IOException
    {
        byte[] block = new byte[len];
        System.arraycopy(b, off, block, 0, len);
        send(Protocol.TYPE_4, seq++, block);
    }

    @Override
    public void write(int b) throws IOException
    {
        write(new byte[] { (byte) b }, 0, 1);
    }

    /** End of the stream -> Type 5: SEQF || E( SEQF || "END" || random string ) */
    @Override
    public void close() throws IOException
    {
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        byte[] endBlock = Utils.concat(Utils.concat(Utils.longToBytes(seq), "END".getBytes(StandardCharsets.UTF_8)),
                                       Utils.toHex(random).getBytes(StandardCharsets.UTF_8));
        send(Protocol.TYPE_5, seq, endBlock);
    }

    private void send(int type, long seq, byte[] body) throws IOException
    {
        try
        {
            ch.sendSeqClear(type, seq, body);
        }
        catch (CryptoException e)
        {
            throw new IOException(e.getMessage(), e);
        }
    }
}