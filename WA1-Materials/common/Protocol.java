/**
 * Constants of the Secure Streaming Protocol (every message: Header || Payload)
 */
public class Protocol
{
    // Version:Release
    public static final int VERSION = 1;
    public static final int RELEASE = 1;

    // Message types
    public static final int TYPE_1   = 1;     // first message of the handshake  (Proxy -> Server)
    public static final int TYPE_2   = 2;     // second message of the handshake (Server -> Proxy)
    public static final int TYPE_3   = 3;     // third message of the handshake  (Proxy -> Server)
    public static final int TYPE_4   = 4;     // encrypted block of the stream   (Server -> Proxy)
    public static final int TYPE_5   = 5;     // last block of the stream        (Server -> Proxy)
    public static final int TYPE_255 = 255;   // error alert

    public static final int HEADER_SIZE = 2 + 2 + 1 + 4;   // version, release, type, size (bytes)

    // Largest payload accepted
    public static final int MAX_PAYLOAD = 1024 * 1024;

    // Alert codes
    public static final int ALERT_UNEXPECTED_MESSAGE = 1;  // message type not expected now
    public static final int ALERT_BAD_VERSION        = 2;  // version:release is not 1:1
    public static final int ALERT_MALFORMED          = 3;  // payload cannot be parsed / wrong size
    public static final int ALERT_INTEGRITY          = 4;  // decryption / tag / MAC check failed
    public static final int ALERT_BAD_SEQUENCE       = 5;  // replayed, duplicated, reordered or missing message
    public static final int ALERT_CONFIG_REJECTED    = 6;  // proposed configuration not compatible
    public static final int ALERT_BAD_CHALLENGE      = 7;  // wrong response R to SRV
    public static final int ALERT_MEDIA_NOT_FOUND    = 8;  // not used: a missing movie gets an HTTP 404 inside the stream

    /**
     * Name of an alert code
     *
     * @param code : alert code
     * @return name : ex. "INTEGRITY_FAILURE"
     */
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