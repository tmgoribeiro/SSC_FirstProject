import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * The Proxy reads the movie from this stream instead of the socket
 * (so the provided relayFromOrigin stays almost unchanged):
 *   Type 4:  SEQB || E( block )                          -> read(...) returns the decrypted block
 *   Type 5:  SEQF || E( SEQF || "END" || random string )   -> end of the stream, read(...) returns -1
 * Each block must have the next SEQ and pass the integrity check (WA1 2.1).
 * A violation is thrown as IOException whose cause is the ProtocolException
 * (InputStream.read can only throw IOException), so the caller can send the alert.
 */
public class SecureInputStream extends InputStream
{
    private final SecureChannel ch;
    private long seq;
    private byte[] block = new byte[0];
    private int pos = 0;
    private boolean end = false;

    public long blocksReceived = 0;                 // metrics (WA1 section 4)

    public SecureInputStream(SecureChannel ch, long firstBlockSeq)
    {
        this.ch = ch;
        this.seq = firstBlockSeq;
    }

    /** Returns (part of) the current decrypted block: one block per read, as the socket did. */
    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        if (!nextBlock()) return -1;
        int n = Math.min(len, block.length - pos);
        System.arraycopy(block, pos, b, off, n);
        pos += n;
        return n;
    }

    @Override
    public int read() throws IOException
    {
        if (!nextBlock()) return -1;
        return block[pos++] & 0xff;
    }    
    /** If the current block was all read, receive the next one; false at the END. */
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
            throw new IOException(e.getMessage(), e);
        }
        return pos < block.length;
    }




}