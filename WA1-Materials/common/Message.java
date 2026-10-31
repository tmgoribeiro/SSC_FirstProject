/**
 * One message of the protocol, as received: Header (type) || Payload.
 */
public class Message
{
    public final int type;
    public final byte[] payload;

    public Message(int type, byte[] payload)
    {
        this.type = type;
        this.payload = payload;
    }
}