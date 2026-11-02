import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Sends and receives messages of the Secure Streaming Protocol (WA1 2.2.3) over
 * one TCP connection:   Header || Payload
 *
 *   Header (clear): version (2) || release (2) || type (1) || size of payload (4)
 *
 * As Lab 2 SendEncrypt / ReceiveDecrypt:
 *   DataOutputStream os = new DataOutputStream(s.getOutputStream());
 *   os.writeInt(ciphertext.length); os.write(ciphertext);
 *   DataInputStream is = new DataInputStream(s.getInputStream());
 *   ciphertext = new byte[is.readInt()]; is.read(ciphertext);
 *
 * Protected payloads use CryptoSuite (Passo 2) and SEQUENCE NUMBERS:
 *   Types 2, 3:  E( SEQ || body )           AAD = version || release || type
 *   Types 4, 5:  SEQ || E( body )           AAD = version || release || type || SEQ
 * The receiver accepts ONLY the next expected SEQ, so replayed, duplicated,
 * reordered, missing (dropped) or injected messages are detected (WA1 2.1).
 * The header fields are in the AAD, so they cannot be changed either
 * (e.g. a type 4 block cannot be turned into a type 5 end-of-stream).
 */
public class SecureChannel
{
    private final DataInputStream in;
    private final DataOutputStream out;
    private final CryptoSuite suite;

    // metrics (WA1 section 4): bytes really sent / received on the network
    public long bytesSent = 0;
    public long bytesReceived = 0;

    public SecureChannel(InputStream in, OutputStream out, CryptoSuite suite)
    {
        this.in = new DataInputStream(in);       // as ReceiveDecrypt
        this.out = new DataOutputStream(out);    // as SendEncrypt
        this.suite = suite;
    }

    // =============================================================== Header || Payload

    /**
     * Send one message: Header || Payload.
     * The fields are written as SendEncrypt does (writeShort, writeByte, writeInt, write),
     * into one buffer that is then sent at once: one TCP write per message, so no
     * small separate packets (that could delay the video).
     */
    public void send(int type, byte[] payload) throws IOException
    {
        ByteArrayOutputStream message = new ByteArrayOutputStream();   // as HttpUtil (base code)
        DataOutputStream os = new DataOutputStream(message);
        os.writeShort(Protocol.VERSION);
        os.writeShort(Protocol.RELEASE);
        os.writeByte(type);
        os.writeInt(payload.length);            // as SendEncrypt: os.writeInt(ciphertext.length)
        os.write(payload);                      //                 os.write(ciphertext)

        out.write(message.toByteArray());
        out.flush();
        bytesSent += Protocol.HEADER_SIZE + payload.length;
    }

    /**
     * Receive one message. An error alert (type 255) from the other side is
     * thrown as AlertException; a wrong header as ProtocolException.
     */
    public Message receive() throws IOException, ProtocolException, AlertException
    {
        int version = in.readUnsignedShort();
        int release = in.readUnsignedShort();
        int type    = in.readUnsignedByte();
        int size    = in.readInt();            // as ReceiveDecrypt: is.readInt()

        if (version != Protocol.VERSION || release != Protocol.RELEASE)
            throw new ProtocolException(Protocol.ALERT_BAD_VERSION, "version " + version + ":" + release);
        if (size < 0 || size > Protocol.MAX_PAYLOAD)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "payload size " + size);

        byte[] payload = new byte[size];
        in.readFully(payload);                 // ReceiveDecrypt uses is.read(), that may read
                                               // LESS than asked: readFully reads all the bytes
        bytesReceived += Protocol.HEADER_SIZE + size;

        if (type == Protocol.TYPE_255)
        {
            // alert: code (1 byte) || reason (text)
            int code = payload.length > 0 ? payload[0] & 0xff : 0;
            String reason = payload.length > 1 ? new String(payload, 1, payload.length - 1, StandardCharsets.UTF_8) : "";
            throw new AlertException(code, reason);
        }
        return new Message(type, payload);
    }

    /** Receive one message that MUST be of the given type. */
    public Message receive(int expectedType) throws IOException, ProtocolException, AlertException
    {
        Message m = receive();
        if (m.type != expectedType)
            throw new ProtocolException(Protocol.ALERT_UNEXPECTED_MESSAGE,
                                        "expected type " + expectedType + ", got type " + m.type);
        return m;
    }

    /** Send an error alert (type 255): code (1 byte) || reason. In clear (there may be no shared key). */
    public void sendAlert(int code, String reason)
    {
        try
        {
            byte[] text = (reason == null ? "" : reason).getBytes(StandardCharsets.UTF_8);
            send(Protocol.TYPE_255, Utils.concat(new byte[] { (byte) code }, text));
        }
        catch (IOException e)
        {
            // the other side is already gone: nothing to do (as SendEncrypt: catch ... { })
        }
    }

    // ===================================== Types 2, 3:  E( SEQ || body )

    /** Encrypt SEQ || body and send it (handshake messages 2 and 3). */
    public void sendSeqInside(int type, long seq, byte[] body) throws IOException, CryptoException
    {
        byte[] plaintext = Utils.concat(Utils.longToBytes(seq), body);
        send(type, suite.encrypt(plaintext, aad(type)));
    }

    /** Decrypt a type 2 / 3 message, check its SEQ and return the body. */
    public byte[] openSeqInside(Message m, long expectedSeq) throws ProtocolException
    {
        byte[] plaintext = decrypt(m.payload, aad(m.type));
        if (plaintext.length < 8)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "no sequence number");
        long seq = Utils.bytesToLong(plaintext, 0);
        checkSeq(seq, expectedSeq);
        byte[] body = new byte[plaintext.length - 8];
        System.arraycopy(plaintext, 8, body, 0, body.length);
        return body;
    }

    // ===================================== Types 4, 5:  SEQ || E( body )

    /** Send SEQ (clear) || E(body); the SEQ is also in the AAD (stream blocks 4 and 5). */
    public void sendSeqClear(int type, long seq, byte[] body) throws IOException, CryptoException
    {
        byte[] encrypted = suite.encrypt(body, aad(type, seq));
        send(type, Utils.concat(Utils.longToBytes(seq), encrypted));
    }

    /** Check the clear SEQ FIRST (cheap rejection of replays), then decrypt the block. */
    public byte[] openSeqClear(Message m, long expectedSeq) throws ProtocolException
    {
        if (m.payload.length < 8)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "no sequence number");
        long seq = Utils.bytesToLong(m.payload, 0);
        checkSeq(seq, expectedSeq);
        byte[] encrypted = new byte[m.payload.length - 8];
        System.arraycopy(m.payload, 8, encrypted, 0, encrypted.length);
        return decrypt(encrypted, aad(m.type, seq));
    }

    // =============================================================== helpers

    /** AAD = version || release || type   (the header fields sent in clear). */
    private static byte[] aad(int type)
    {
        return new byte[] { (byte)(Protocol.VERSION >> 8), (byte) Protocol.VERSION,
                            (byte)(Protocol.RELEASE >> 8), (byte) Protocol.RELEASE,
                            (byte) type };
    }

    /** AAD = version || release || type || SEQ   (for blocks, where the SEQ goes in clear). */
    private static byte[] aad(int type, long seq)
    {
        return Utils.concat(aad(type), Utils.longToBytes(seq));
    }

    private byte[] decrypt(byte[] encrypted, byte[] aad) throws ProtocolException
    {
        try
        {
            return suite.decrypt(encrypted, aad);
        }
        catch (CryptoException e)
        {
            throw new ProtocolException(Protocol.ALERT_INTEGRITY, e.getMessage());
        }
    }

    /** Only the next expected sequence number is accepted. */
    private static void checkSeq(long seq, long expectedSeq) throws ProtocolException
    {
        if (seq != expectedSeq)
            throw new ProtocolException(Protocol.ALERT_BAD_SEQUENCE,
                "expected SEQ " + expectedSeq + ", got " + seq
                + (seq < expectedSeq ? " (replayed or duplicated message)" : " (reordered or missing message)"));
    }
}