import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Initial negotiation handshake of the Secure Streaming Protocol (WA1 2.2.1, 2.2.3).
 *
 *   Proxy                                                         Stream Server
 *     | -- Type 1 (clear):  SEQX || PCC  -------------------------->  | PCC compatible with
 *     |                                                               | sservercrypto.config?
 *     |                                                               |   no  -> error alert
 *     | <-- Type 2:  E( SEQY || SRV || CCC )  ------------------------ |   yes -> SRV (256 bits)
 *     |  CCC == my PCC?                                               |
 *     | -- Type 3:  E( SEQZ || R || MEDIA )  ------------------------>  | R == SHA256(SRV)?
 *     |                                                               |   -> start the stream
 *
 *   SEQX random; SEQY = SEQX + 1; SEQZ = SEQY + 1; the stream blocks start at SEQZ + 1.
 *   SEQ: 8 bytes; SRV and R: 32 bytes; PCC, CCC, MEDIA: text, at the end of the message.
 *
 * Any violation is thrown as ProtocolException: the caller sends the error alert (type 255).
 *
 * Based on:
 *  - SHA-256: Lab 3.1 FileHash / HashExample (MessageDigest.getInstance("SHA-256"), digest)
 *  - random values: SecureRandom.nextBytes (Lab 3.2 SimpleGCMExample, Lab 3.1 createCtrIvForAES)
 *  - joining / splitting fields: System.arraycopy (Lab 3.2 SimpleGCMExample: nonce || ciphertext)
 *  - text <-> bytes: getBytes / new String with UTF-8 (Lab 3.1 ChaCha20.java)
 *  - comparing R: MessageDigest.isEqual (Lab 3.2 HmacExample.verify)
 */
public class Handshake
{
    public static final int SEQ_SIZE = 8;             // bytes
    public static final int SRV_SIZE = 32;            // "SRV: a 256 bit nonce"
    public static final int R_SIZE   = 32;            // SHA-256 output

    /** What both sides know when the handshake succeeds. */
    public static class Result
    {
        public final String media;                    // the movie requested in message 3
        public final long firstBlockSeq;              // SEQZ + 1: SEQ of the first stream block

        Result(String media, long firstBlockSeq)
        {
            this.media = media;
            this.firstBlockSeq = firstBlockSeq;
        }
    }

    // =================================================================== Proxy side

    /** Run the handshake as the Proxy, asking for the movie 'media'. */
    public static Result proxy(SecureChannel ch, CryptoConfig cfg, String media)
        throws IOException, ProtocolException, AlertException, CryptoException
    {
        SecureRandom random = new SecureRandom();

        // ---- Type 1 (clear): SEQX || PCC
        byte[] seqBytes = new byte[SEQ_SIZE];
        random.nextBytes(seqBytes);                              // random, as createCtrIvForAES
        seqBytes[0] &= 0x3F;                                     // positive, with room to grow
        long seqX = Utils.bytesToLong(seqBytes, 0);
        byte[] pcc = cfg.proposal().getBytes(StandardCharsets.UTF_8);   // PCC = ALG/MODE/IV/Padding
        ch.send(Protocol.TYPE_1, Utils.concat(seqBytes, pcc));

        // ---- Type 2: E( SEQY || SRV || CCC ),  SEQY = SEQX + 1
        byte[] body2 = ch.openSeqInside(ch.receive(Protocol.TYPE_2), seqX + 1);
        if (body2.length < SRV_SIZE)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "bad type 2 message");
        byte[] srv = new byte[SRV_SIZE];
        System.arraycopy(body2, 0, srv, 0, SRV_SIZE);
        String ccc = new String(body2, SRV_SIZE, body2.length - SRV_SIZE, StandardCharsets.UTF_8);

        // The confirmation must be exactly what we proposed. Message 1 goes in clear:
        // this (encrypted and authenticated) check detects a changed proposal.
        if (!ccc.equals(cfg.proposal()))
            throw new ProtocolException(Protocol.ALERT_CONFIG_REJECTED,
                                        "server confirmed " + ccc + ", proposed " + cfg.proposal());

        // ---- Type 3: E( SEQZ || R || MEDIA ),  SEQZ = SEQY + 1,  R = SHA256(SRV)
        byte[] r = sha256(srv);
        byte[] body3 = Utils.concat(r, media.getBytes(StandardCharsets.UTF_8));
        ch.sendSeqInside(Protocol.TYPE_3, seqX + 2, body3);

        return new Result(media, seqX + 3);
    }

    // =================================================================== Server side

    /** Run the handshake as the Stream Server. */
    public static Result server(SecureChannel ch, CryptoConfig cfg)
        throws IOException, ProtocolException, AlertException, CryptoException
    {
        // ---- Type 1 (clear): SEQX || PCC
        Message m1 = ch.receive(Protocol.TYPE_1);
        if (m1.payload.length < SEQ_SIZE)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "bad type 1 message");
        long seqX = Utils.bytesToLong(m1.payload, 0);
        String pcc = new String(m1.payload, SEQ_SIZE, m1.payload.length - SEQ_SIZE, StandardCharsets.UTF_8);

        // "see if the proposed cryptographic configurations are compatible with the
        //  definitions in the file sservercrypto.config ... Otherwise, an error message"
        if (!pcc.equals(cfg.proposal()))
            throw new ProtocolException(Protocol.ALERT_CONFIG_REJECTED,
                                        "proposal " + pcc + " is not compatible with " + cfg.proposal());

        // ---- Type 2: E( SEQY || SRV || CCC )
        byte[] srv = new byte[SRV_SIZE];
        new SecureRandom().nextBytes(srv);                       // "a 256 bit nonce ... as a challenge"
        byte[] ccc = cfg.proposal().getBytes(StandardCharsets.UTF_8);   // confirmation of the configuration
        ch.sendSeqInside(Protocol.TYPE_2, seqX + 1, Utils.concat(srv, ccc));

        // ---- Type 3: E( SEQZ || R || MEDIA )
        byte[] body3 = ch.openSeqInside(ch.receive(Protocol.TYPE_3), seqX + 2);
        if (body3.length < R_SIZE)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "bad type 3 message");
        byte[] r = new byte[R_SIZE];
        System.arraycopy(body3, 0, r, 0, R_SIZE);
        String media = new String(body3, R_SIZE, body3.length - R_SIZE, StandardCharsets.UTF_8);

        // R must be SHA256(SRV) of THIS session (constant-time comparison, as HmacExample.verify)
        if (!MessageDigest.isEqual(r, sha256(srv)))
            throw new ProtocolException(Protocol.ALERT_BAD_CHALLENGE, "wrong response R to the SRV challenge");

        return new Result(media, seqX + 3);
    }


    /**
     * SHA-256, as in Lab 3.1 FileHash / HashExample:
     *   MessageDigest digest = MessageDigest.getInstance("SHA-256"); digest.digest(...)
     * Errors wrapped in a CryptoException, as in Lab 2 CryptoStuff.
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