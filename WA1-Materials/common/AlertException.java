/**
 * An error-alert message (type 255) received from the other side.
 */
public class AlertException extends Exception
{
    public final int alert;

    public AlertException(int alert, String reason)
    {
        super("received alert " + Protocol.alertName(alert) + (reason.isEmpty() ? "" : ": " + reason));
        this.alert = alert;
    }
}