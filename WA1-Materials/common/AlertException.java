/**
 * Error alert (type 255) received from the other side
 */
public class AlertException extends Exception
{
    public final int alert;

    /**
     * Create the exception for a received alert
     *
     * @param alert : alert code
     * @param reason : text sent with the alert
     */
    public AlertException(int alert, String reason)
    {
        super("received alert " + Protocol.alertName(alert) + (reason.isEmpty() ? "" : ": " + reason));
        this.alert = alert;
    }
}