/**
 * Violation of the Secure Streaming Protocol detected locally
 */
public class ProtocolException extends Exception
{
    public final int alert;

    /**
     * Create the exception with the alert to send to the other side
     *
     * @param alert : alert code
     * @param message : description of the violation
     */
    public ProtocolException(int alert, String message)
    {
        super(Protocol.alertName(alert) + ": " + message);
        this.alert = alert;
    }
}