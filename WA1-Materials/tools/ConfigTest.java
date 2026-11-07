import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reads each configuration file, shows its values and checks that Java supports the configured cipher and MAC
 */
public class ConfigTest
{
    /**
     * Check every configuration file and print VALID or REFUSED
     *
     * @param args : configuration files
     */
    public static void main(String[] args)
    {
        if (args.length == 0)
        {
            System.out.println("Use: java ConfigTest <config file> ...");
            System.exit(-1);
        }
        for (String file : args)
        {
            System.out.println("======================================");
            System.out.println(file);
            try
            {
                CryptoConfig c = CryptoConfig.load(file);
                System.out.println("Algorithm      : " + c.algorithm);
                System.out.println("Mode           : " + c.mode);
                System.out.println("IV             : " + (c.iv == null ? "NULL" : Utils.toHex(c.iv)));
                System.out.println("IV size        : " + c.ivSize + " bits");
                System.out.println("Padding        : " + c.padding);
                System.out.println("MAC            : " + c.macAlgorithm);
                System.out.println("Key            : " + c.symKeySize + " bits");
                System.out.println("MAC key        : " + c.macKeySize + " bits");
                System.out.println("AEAD?          : " + c.isAEAD());
                System.out.println("Transformation : " + c.transformation());
                System.out.println("Proposal (PCC) : " + c.proposal());

                Cipher cipher = Cipher.getInstance(c.transformation());
                SecretKeySpec key = new SecretKeySpec(c.symKey, c.algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, key);   // fails if the key does not fit the algorithm
                System.out.println("Cipher         : OK (provider " + cipher.getProvider().getName() + ")");
                if (c.macAlgorithm != null)
                {
                    String javaName = c.macJavaName();
                    Mac mac = Mac.getInstance(javaName);
                    mac.init(new SecretKeySpec(c.macKey, javaName));
                    System.out.println("MAC            : OK (" + javaName + ", " + mac.getMacLength() + " bytes)");
                }
                System.out.println("VALID");
            }
            catch (Exception e)
            {
                System.out.println("REFUSED: " + e.getMessage());
            }
        }
    }
}