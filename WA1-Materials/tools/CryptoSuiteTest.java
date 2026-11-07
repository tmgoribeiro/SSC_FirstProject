import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Tests the encryption of each configuration: round-trip, fresh nonce, tampering rejected and bytes added per block
 *
 * Use: java CryptoSuiteTest <config file> ...
 */
public class CryptoSuiteTest
{
    static SecureRandom random = new SecureRandom();

    /**
     * Run the tests for every configuration file
     *
     * @param args : configuration files
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length == 0)
        {
            System.out.println("Use: java CryptoSuiteTest <config file> ...");
            System.exit(-1);
        }
        int failures = 0;
        for (String file : args)
        {
            System.out.println("======================================");
            System.out.println(file);
            CryptoConfig cfg;
            try
            {
                cfg = CryptoConfig.load(file);
            }
            catch (CryptoException e)
            {
                System.out.println("REFUSED: " + e.getMessage());
                continue;
            }
            System.out.println("Config: " + cfg.proposal() + (cfg.macAlgorithm != null ? " + " + cfg.macAlgorithm : ""));
            CryptoSuite sender = new CryptoSuite(cfg);
            CryptoSuite receiver = new CryptoSuite(cfg);

            try
            {
                // 1. round-trip, 2. fresh nonce, 4. every change rejected
                boolean roundTrip = true, freshNonce = true, allRejected = true;
                for (int size : new int[] { 0, 1, 15, 16, 17, 1023, 1024 })
                {
                    byte[] msg = randomBytes(size);
                    byte[] aad = randomBytes(13);
                    byte[] c1 = sender.encrypt(msg, aad);
                    roundTrip &= Arrays.equals(receiver.decrypt(c1, aad), msg);
                    freshNonce &= !Arrays.equals(c1, sender.encrypt(msg, aad));

                    for (int i = 0; i < c1.length; i++)                 // every byte, one bit
                    {
                        byte[] t = c1.clone();
                        t[i] ^= 0x01;
                        allRejected &= rejected(receiver, t, aad);
                    }
                    byte[] otherAad = aad.clone();
                    otherAad[0] ^= 0x01;
                    allRejected &= rejected(receiver, c1, otherAad);                         // header changed
                    allRejected &= rejected(receiver, Arrays.copyOf(c1, c1.length - 1), aad); // truncated
                }

                // 3. Mallory changes one digit of the ciphertext
                String input = "Transfer 0000100 to AC 1234-5678";
                byte[] aad = "header".getBytes();
                byte[] sent = sender.encrypt(input.getBytes(), aad);
                byte[] tampered = sent.clone();
                // the ciphertext starts after the nonce; char 9 is the first '0' of "0000100"
                tampered[cfg.ivSize / 8 + 9] ^= '0' ^ '9';
                String mallory;
                try
                {
                    mallory = "ACCEPTED (!!): " + new String(receiver.decrypt(tampered, aad));
                }
                catch (CryptoException e)
                {
                    mallory = "REJECTED (" + e.getMessage() + ")";
                }

                // 5. size added to one 1024-byte block
                int added = sender.encrypt(new byte[1024], aad).length - 1024;

                System.out.println("1. round-trip              : " + (roundTrip ? "OK" : "FAIL"));
                System.out.println("2. new nonce every message : " + (freshNonce ? "OK" : "FAIL"));
                System.out.println("3. Mallory flips a digit   : " + mallory);
                System.out.println("4. every bit/AAD/truncated : " + (allRejected ? "all REJECTED" : "FAIL: something accepted"));
                System.out.println("5. bytes added per 1KB     : +" + added + " (" + String.format("%.1f", 100.0 * added / 1024) + "%)");
                if (!roundTrip || !freshNonce || !allRejected || mallory.startsWith("ACCEPTED")) failures++;
            }
            catch (CryptoException e)
            {
                System.out.println("REFUSED: " + e.getMessage()
                                   + (e.getCause() != null ? " (" + e.getCause().getMessage() + ")" : ""));
            }
        }
        System.out.println("======================================");
        System.out.println(failures == 0 ? "ALL TESTS PASSED" : failures + " CONFIG(S) FAILED");
    }

    /**
     * Check that a message is rejected by the receiver
     *
     * @param s : crypto suite of the receiver
     * @param msg : encrypted message
     * @param aad : associated data
     * @return rejected : true if decryption failed
     */
    static boolean rejected(CryptoSuite s, byte[] msg, byte[] aad)
    {
        try
        {
            s.decrypt(msg, aad);
            return false;
        }
        catch (CryptoException e)
        {
            return true;
        }
    }

    /**
     * Generate random bytes
     *
     * @param n : number of bytes
     * @return bytes : random array
     */
    static byte[] randomBytes(int n)
    {
        byte[] b = new byte[n];
        random.nextBytes(b);
        return b;
    }
}