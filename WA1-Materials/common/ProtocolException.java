/**
 * A violation of the Secure Streaming Protocol detected locally.
 * It is answered with an error-alert message (type 255) with this alert code
 * (WA1 2.2.1: "any violation of the correct flow or correct processing of expected
 * messages must be notified with an alert-error message").
 */
public class ProtocolException extends Exception
{
    public final int alert;

    public ProtocolException(int alert, String message)
    {
        super(Protocol.alertName(alert) + ": " + message);
        this.alert = alert;
    }
}