import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Stream written by the Stream Server instead of the socket: each write is sent
 * as an encrypted block (type 4) and close() sends the END (type 5)
 */
public class SecureOutputStream extends OutputStream
{
    private final SecureChannel ch;
    private long seq;                               // sequence number of the next block

    /**
     * Create the stream for one session
     *
     * @param ch : secure channel to the proxy
     * @param firstBlockSeq : sequence number of the first block
     */
    public SecureOutputStream(SecureChannel ch, long firstBlockSeq)
    {
        this.ch = ch;
        this.seq = firstBlockSeq;
    }

    /**
     * Send one block as a type 4 message: SEQB || E(block)
     *
     * @param b : data to send
     * @param off : position of the block in b
     * @param len : size of the block
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException
    {
        byte[] block = new byte[len];
        System.arraycopy(b, off, block, 0, len);
        send(Protocol.TYPE_4, seq++, block);
    }

    /**
     * Send one byte as a block
     *
     * @param b : byte to send
     */
    @Override
    public void write(int b) throws IOException
    {
        write(new byte[] { (byte) b }, 0, 1);
    }

    /**
     * End the stream with a type 5 message: SEQF || E(SEQF || "END" || random string)
     */
    @Override
    public void close() throws IOException
    {
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        byte[] endBlock = Utils.concat(Utils.concat(Utils.longToBytes(seq), "END".getBytes(StandardCharsets.UTF_8)),
                                       Utils.toHex(random).getBytes(StandardCharsets.UTF_8));
        send(Protocol.TYPE_5, seq, endBlock);
    }

    /**
     * Encrypt and send one stream message
     *
     * @param type : message type (4 or 5)
     * @param seq : sequence number
     * @param body : data to encrypt
     */
    private void send(int type, long seq, byte[] body) throws IOException
    {
        try
        {
            ch.sendSeqClear(type, seq, body);
        }
        catch (CryptoException e)
        {
            throw new IOException(e.getMessage(), e);   // an OutputStream can only throw IOException
        }
    }
}