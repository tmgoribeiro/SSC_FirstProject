/**
 * Constants of the Secure Streaming Protocol (WA1, section 2.2.3).
 *
 * Every message:   Header || Payload
 *
 *   Header (always in plaintext):
 *     HS Version (2 bytes) || HS Release (2 bytes) || HS message type (1 byte) || Size of Payload (4 bytes)
 *
 *   Payload, depending on the message type:
 *     Type 1   (Proxy -> Server, clear)      SEQX || PCC
 *     Type 2   (Server -> Proxy, encrypted)  E( SEQY || SRV || CCC )            SEQY = SEQX + 1
 *     Type 3   (Proxy -> Server, encrypted)  E( SEQZ || R || MEDIA )            SEQZ = SEQY + 1, R = SHA256(SRV)
 *     Type 4   (Server -> Proxy)             SEQB || E( block )                 SEQB = SEQZ + 1, + 1, ...
 *     Type 5   (Server -> Proxy)             SEQF || E( SEQF || "END" || random string )
 *     Type 255 (error alert)
 *
 * The 4-byte size and the encoding with DataOutputStream (writeShort, writeByte,
 * writeInt, writeLong, writeUTF) follow Lab 2: SendEncrypt (os.writeInt(ciphertext.length);
 * os.write(ciphertext)) and FileTransferClient (dos.writeUTF(name); dos.writeLong(size)).
 */
public class Protocol
{
    // HS Version:Release -- "For Work Assignment 1, version:release is 1:1"
    public static final int VERSION = 1;
    public static final int RELEASE = 1;

    // HS message types
    public static final int TYPE_1   = 1;     // first message of the handshake  (Proxy -> Server)
    public static final int TYPE_2   = 2;     // second message of the handshake (Server -> Proxy)
    public static final int TYPE_3   = 3;     // third message of the handshake  (Proxy -> Server)
    public static final int TYPE_4   = 4;     // encrypted block of the stream   (Server -> Proxy)
    public static final int TYPE_5   = 5;     // last block of the stream        (Server -> Proxy)
    public static final int TYPE_255 = 255;   // error alert

    public static final int HEADER_SIZE = 2 + 2 + 1 + 4;   // bytes

    // Largest payload accepted: a forged "Size of Payload" cannot make us allocate GBs (DoS)
    public static final int MAX_PAYLOAD = 1024 * 1024;

    // Alert codes (payload of a type 255 message: code (1 byte) || reason (writeUTF))
    public static final int ALERT_UNEXPECTED_MESSAGE = 1;  // message type not expected now
    public static final int ALERT_BAD_VERSION        = 2;  // version:release is not 1:1
    public static final int ALERT_MALFORMED          = 3;  // payload cannot be parsed / wrong size
    public static final int ALERT_INTEGRITY          = 4;  // decryption / tag / MAC check failed
    public static final int ALERT_BAD_SEQUENCE       = 5;  // replayed, duplicated, reordered or missing message
    public static final int ALERT_CONFIG_REJECTED    = 6;  // proposed configuration not compatible (Passo 4)
    public static final int ALERT_BAD_CHALLENGE      = 7;  // wrong response R to SRV (Passo 4)
    public static final int ALERT_MEDIA_NOT_FOUND    = 8;  // requested movie does not exist (Passo 5)

    public static String alertName(int code)
    {
        switch (code)
        {
            case ALERT_UNEXPECTED_MESSAGE: return "UNEXPECTED_MESSAGE";
            case ALERT_BAD_VERSION:        return "BAD_VERSION";
            case ALERT_MALFORMED:          return "MALFORMED";
            case ALERT_INTEGRITY:          return "INTEGRITY_FAILURE";
            case ALERT_BAD_SEQUENCE:       return "BAD_SEQUENCE";
            case ALERT_CONFIG_REJECTED:    return "CONFIG_REJECTED";
            case ALERT_BAD_CHALLENGE:      return "BAD_CHALLENGE";
            case ALERT_MEDIA_NOT_FOUND:    return "MEDIA_NOT_FOUND";
            default:                       return "ALERT_" + code;
        }
    }
}