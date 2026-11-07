import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Initial negotiation handshake of the Secure Streaming Protocol (messages 1, 2, 3)
 */
public class Handshake
{
    public static final int SEQ_SIZE = 8;             // bytes
    public static final int SRV_SIZE = 32;            // 256-bit challenge
    public static final int R_SIZE   = 32;            // SHA-256 output

    /**
     * Result of a successful handshake
     */
    public static class Result
    {
        public final String media;                    // the movie requested in message 3
        public final long firstBlockSeq;              // SEQZ + 1: SEQ of the first stream block

        /**
         * Create the result of the handshake
         *
         * @param media : requested movie
         * @param firstBlockSeq : sequence number of the first stream block
         */
        Result(String media, long firstBlockSeq)
        {
            this.media = media;
            this.firstBlockSeq = firstBlockSeq;
        }
    }

    // Proxy side

    /**
     * Run the handshake as the Proxy and request a movie
     *
     * @param ch : secure channel to the server
     * @param cfg : proxy configuration
     * @param media : movie to request
     * @return result : requested movie and SEQ of the first block
     */
    public static Result proxy(SecureChannel ch, CryptoConfig cfg, String media)
        throws IOException, ProtocolException, AlertException, CryptoException
    {
        SecureRandom random = new SecureRandom();

        // Type 1 (clear): SEQX || PCC
        byte[] seqBytes = new byte[SEQ_SIZE];
        random.nextBytes(seqBytes);                             
        seqBytes[0] &= 0x3F;                                     // positive, with room to grow
        long seqX = Utils.bytesToLong(seqBytes, 0);
        byte[] pcc = cfg.proposal().getBytes(StandardCharsets.UTF_8);  
        ch.send(Protocol.TYPE_1, Utils.concat(seqBytes, pcc));

        // Type 2: E( SEQY || SRV || CCC ),  SEQY = SEQX + 1
        byte[] body2 = ch.openSeqInside(ch.receive(Protocol.TYPE_2), seqX + 1);
        if (body2.length < SRV_SIZE)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "bad type 2 message");
        byte[] srv = new byte[SRV_SIZE];
        System.arraycopy(body2, 0, srv, 0, SRV_SIZE);
        String ccc = new String(body2, SRV_SIZE, body2.length - SRV_SIZE, StandardCharsets.UTF_8);

        // the confirmation must be exactly the proposal (detects a changed message 1)
        if (!ccc.equals(cfg.proposal()))
            throw new ProtocolException(Protocol.ALERT_CONFIG_REJECTED,
                                        "server confirmed " + ccc + ", proposed " + cfg.proposal());

        // Type 3: E( SEQZ || R || MEDIA ),  SEQZ = SEQY + 1,  R = SHA256(SRV)
        byte[] r = sha256(srv);
        byte[] body3 = Utils.concat(r, media.getBytes(StandardCharsets.UTF_8));
        ch.sendSeqInside(Protocol.TYPE_3, seqX + 2, body3);

        return new Result(media, seqX + 3);
    }

    // Server side

    /**
     * Run the handshake as the Stream Server
     *
     * @param ch : secure channel to the proxy
     * @param cfg : server configuration
     * @return result : requested movie and SEQ of the first block
     */
    public static Result server(SecureChannel ch, CryptoConfig cfg)
        throws IOException, ProtocolException, AlertException, CryptoException
    {
        // Type 1 (clear): SEQX || PCC
        Message m1 = ch.receive(Protocol.TYPE_1);
        if (m1.payload.length < SEQ_SIZE)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "bad type 1 message");
        long seqX = Utils.bytesToLong(m1.payload, 0);
        String pcc = new String(m1.payload, SEQ_SIZE, m1.payload.length - SEQ_SIZE, StandardCharsets.UTF_8);

        // the proposal must match the server configuration
        if (!pcc.equals(cfg.proposal()))
            throw new ProtocolException(Protocol.ALERT_CONFIG_REJECTED,
                                        "proposal " + pcc + " is not compatible with " + cfg.proposal());

        // Type 2: E( SEQY || SRV || CCC )
        byte[] srv = new byte[SRV_SIZE];
        new SecureRandom().nextBytes(srv);                       // random challenge
        byte[] ccc = cfg.proposal().getBytes(StandardCharsets.UTF_8);   // confirmation of the configuration
        ch.sendSeqInside(Protocol.TYPE_2, seqX + 1, Utils.concat(srv, ccc));

        // Type 3: E( SEQZ || R || MEDIA )
        byte[] body3 = ch.openSeqInside(ch.receive(Protocol.TYPE_3), seqX + 2);
        if (body3.length < R_SIZE)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "bad type 3 message");
        byte[] r = new byte[R_SIZE];
        System.arraycopy(body3, 0, r, 0, R_SIZE);
        String media = new String(body3, R_SIZE, body3.length - R_SIZE, StandardCharsets.UTF_8);

        // R must answer the challenge of THIS session (constant-time comparison)
        if (!MessageDigest.isEqual(r, sha256(srv)))
            throw new ProtocolException(Protocol.ALERT_BAD_CHALLENGE, "wrong response R to the SRV challenge");

        return new Result(media, seqX + 3);
    }

    /**
     * Compute the SHA-256 hash of the data
     *
     * @param data : bytes to hash
     * @return hash : 32-byte SHA-256 digest
     */
    static byte[] sha256(byte[] data) throws CryptoException
    {
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new CryptoException("Error computing SHA-256", ex);
        }
    }
}