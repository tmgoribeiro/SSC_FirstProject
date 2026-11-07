import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Stream read by the Proxy instead of the socket: returns the decrypted blocks
 * (type 4) and ends only with a valid END (type 5)
 */
public class SecureInputStream extends InputStream
{
    private final SecureChannel ch;
    private long seq;                               // next expected sequence number
    private byte[] block = new byte[0];             // current decrypted block
    private int pos = 0;                            // bytes of the block already read
    private boolean end = false;                    // true after a valid END

    public long blocksReceived = 0;                 // metrics 

    /**
     * Create the stream for one session
     *
     * @param ch : secure channel to the server
     * @param firstBlockSeq : sequence number of the first block
     */
    public SecureInputStream(SecureChannel ch, long firstBlockSeq)
    {
        this.ch = ch;
        this.seq = firstBlockSeq;
    }

    /**
     * Read (part of) the current decrypted block, one block per call
     *
     * @param b : buffer where to copy the data
     * @param off : position in the buffer
     * @param len : maximum number of bytes to read
     * @return n : bytes read, or -1 at the END
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        if (!nextBlock()) return -1;
        int n = Math.min(len, block.length - pos);
        System.arraycopy(block, pos, b, off, n);
        pos += n;
        return n;
    }

    /**
     * Read one byte of the current decrypted block
     *
     * @return byte : the byte (0-255), or -1 at the END
     */
    @Override
    public int read() throws IOException
    {
        if (!nextBlock()) return -1;
        return block[pos++] & 0xff;
    }

    /**
     * Receive, decrypt and check the next block when the current one is all read
     *
     * @return more : true if there is data to read, false at the END
     */
    private boolean nextBlock() throws IOException
    {
        try
        {
            while (pos == block.length && !end)
            {
                Message m = ch.receive();
                if (m.type == Protocol.TYPE_4)
                {
                    block = ch.openSeqClear(m, seq++);
                    pos = 0;
                    blocksReceived++;
                }
                else if (m.type == Protocol.TYPE_5)
                {
                    // ENDBLOCK = SEQF || "END" || random string
                    byte[] endBlock = ch.openSeqClear(m, seq);
                    if (endBlock.length < 11 || Utils.bytesToLong(endBlock, 0) != seq
                        || !new String(endBlock, 8, 3, StandardCharsets.UTF_8).equals("END"))
                        throw new ProtocolException(Protocol.ALERT_MALFORMED, "invalid END block");
                    end = true;
                }
                else
                    throw new ProtocolException(Protocol.ALERT_UNEXPECTED_MESSAGE, "expected type 4 or 5, got type " + m.type);
            }
        }
        catch (ProtocolException | AlertException e)
        {
            throw new IOException(e.getMessage(), e);   // the cause is used by the proxy to send the alert
        }
        return pos < block.length;
    }
}