import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Sends and receives Secure Streaming Protocol messages (Header || Payload) over one TCP connection
 */
public class SecureChannel
{
    private final DataInputStream in;
    private final DataOutputStream out;
    private final CryptoSuite suite;

    // metrics: bytes really sent / received on the network
    public long bytesSent = 0;
    public long bytesReceived = 0;

    /**
     * Create a secure channel over the streams of a TCP connection
     *
     * @param in : input stream of the connection
     * @param out : output stream of the connection
     * @param suite : cryptographic suite used to protect the messages
     */
    public SecureChannel(InputStream in, OutputStream out, CryptoSuite suite)
    {
        this.in = new DataInputStream(in);
        this.out = new DataOutputStream(out);
        this.suite = suite;
    }

    // Header || Payload

    /**
     * Send one message (Header || Payload) in a single write
     *
     * @param type : message type
     * @param payload : message payload
     */
    public void send(int type, byte[] payload) throws IOException
    {
        ByteArrayOutputStream message = new ByteArrayOutputStream();   
        DataOutputStream os = new DataOutputStream(message);
        os.writeShort(Protocol.VERSION);
        os.writeShort(Protocol.RELEASE);
        os.writeByte(type);
        os.writeInt(payload.length);           
        os.write(payload);                      

        out.write(message.toByteArray());
        out.flush();
        bytesSent += Protocol.HEADER_SIZE + payload.length;
    }

    /**
     * Receive one message; an alert (type 255) is thrown as AlertException
     *
     * @return message : type and payload of the received message
     */
    public Message receive() throws IOException, ProtocolException, AlertException
    {
        int version = in.readUnsignedShort();
        int release = in.readUnsignedShort();
        int type    = in.readUnsignedByte();
        int size    = in.readInt();            
        if (version != Protocol.VERSION || release != Protocol.RELEASE)
            throw new ProtocolException(Protocol.ALERT_BAD_VERSION, "version " + version + ":" + release);
        if (size < 0 || size > Protocol.MAX_PAYLOAD)
            throw new ProtocolException(Protocol.ALERT_MALFORMED, "payload size " + size);

        byte[] payload = new byte[size];
        in.readFully(payload);                 
                                              
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

    /**
     * Receive one message that must be of the given type
     *
     * @param expectedType : type the message must have
     * @return message : the received message
     */
    public Message receive(int expectedType) throws IOException, ProtocolException, AlertException
    {
        Message m = receive();
        if (m.type != expectedType)
            throw new ProtocolException(Protocol.ALERT_UNEXPECTED_MESSAGE,
                                        "expected type " + expectedType + ", got type " + m.type);
        return m;
    }

    /**
     * Send an error alert (type 255): code || reason
     *
     * @param code : alert code
     * @param reason : text describing the error
     */
    public void sendAlert(int code, String reason)
    {
        try
        {
            byte[] text = (reason == null ? "" : reason).getBytes(StandardCharsets.UTF_8);
            send(Protocol.TYPE_255, Utils.concat(new byte[] { (byte) code }, text));
        }
        catch (IOException e)
        {
            // the other side is already gone: nothing to do 
        }
    }

    // Types 2, 3:  E( SEQ || body )

    /**
     * Encrypt SEQ || body and send it (handshake messages 2 and 3)
     *
     * @param type : message type
     * @param seq : sequence number
     * @param body : data to send after the SEQ
     */
    public void sendSeqInside(int type, long seq, byte[] body) throws IOException, CryptoException
    {
        byte[] plaintext = Utils.concat(Utils.longToBytes(seq), body);
        send(type, suite.encrypt(plaintext, aad(type)));
    }

    /**
     * Decrypt a message 2 / 3 and check its SEQ
     *
     * @param m : received message
     * @param expectedSeq : sequence number it must have
     * @return body : decrypted data after the SEQ
     */
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

    // Types 4, 5:  SEQ || E( body )

    /**
     * Send SEQ (clear) || E(body), with the SEQ in the AAD (stream messages 4 and 5)
     *
     * @param type : message type
     * @param seq : sequence number
     * @param body : data to encrypt
     */
    public void sendSeqClear(int type, long seq, byte[] body) throws IOException, CryptoException
    {
        byte[] encrypted = suite.encrypt(body, aad(type, seq));
        send(type, Utils.concat(Utils.longToBytes(seq), encrypted));
    }

    /**
     * Check the clear SEQ first, then decrypt a message 4 / 5
     *
     * @param m : received message
     * @param expectedSeq : sequence number it must have
     * @return body : decrypted data
     */
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

    /**
     * Build the AAD from the clear header fields: version || release || type
     *
     * @param type : message type
     * @return aad : associated data
     */
    private static byte[] aad(int type)
    {
        return new byte[] { (byte)(Protocol.VERSION >> 8), (byte) Protocol.VERSION,
                            (byte)(Protocol.RELEASE >> 8), (byte) Protocol.RELEASE,
                            (byte) type };
    }

    /**
     * Build the AAD for stream blocks: version || release || type || SEQ
     *
     * @param type : message type
     * @param seq : sequence number sent in clear
     * @return aad : associated data
     */
    private static byte[] aad(int type, long seq)
    {
        return Utils.concat(aad(type), Utils.longToBytes(seq));
    }

    /**
     * Decrypt data; any failure becomes an INTEGRITY_FAILURE protocol error
     *
     * @param encrypted : data to decrypt
     * @param aad : associated data
     * @return plaintext : decrypted data
     */
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

    /**
     * Accept only the next expected sequence number
     *
     * @param seq : received sequence number
     * @param expectedSeq : expected sequence number
     */
    private static void checkSeq(long seq, long expectedSeq) throws ProtocolException
    {
        if (seq != expectedSeq)
            throw new ProtocolException(Protocol.ALERT_BAD_SEQUENCE,
                "expected SEQ " + expectedSeq + ", got " + seq
                + (seq < expectedSeq ? " (replayed or duplicated message)" : " (reordered or missing message)"));
    }
}