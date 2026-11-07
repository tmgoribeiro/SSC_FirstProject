/**
 * One received protocol message: type and payload
 */
public class Message
{
    public final int type;
    public final byte[] payload;

    /**
     * Create a message
     *
     * @param type : message type
     * @param payload : message payload
     */
    public Message(int type, byte[] payload)
    {
        this.type = type;
        this.payload = payload;
    }
}