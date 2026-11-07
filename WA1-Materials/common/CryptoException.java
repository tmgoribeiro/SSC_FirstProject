/**
 * Error in a cryptographic operation or in a configuration file
 */
public class CryptoException extends Exception 
{
     /**
      * Create the exception without a message
      */
     public CryptoException() 
     {
	
     }

     /**
      * Create the exception with a message
      *
      * @param message : description of the error
      */
     public CryptoException(String message) 
     {
        super(message);
     }
    
     /**
      * Create the exception with a message and its cause
      *
      * @param message : description of the error
      * @param throwable : original exception that caused it
      */
     public CryptoException(String message, Throwable throwable) 
     {
	
        super(message, throwable);
     }
}