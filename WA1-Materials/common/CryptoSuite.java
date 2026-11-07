import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts one message with the configured cipher (AEAD or Encrypt-then-MAC)
 */
public class CryptoSuite
{
    private static final int GCM_TAG_LENGTH = 128;   // bits
    private static final int INITIAL_COUNTER = 0;    // ChaCha20 initial block counter

    private final CryptoConfig cfg;
    private final SecretKey key;                     
    private final SecureRandom random = new SecureRandom();

    /**
     * Create the suite for one configuration
     *
     * @param cfg : cryptographic configuration
     */
    public CryptoSuite(CryptoConfig cfg)
    {
        this.cfg = cfg;
        this.key = new SecretKeySpec(cfg.symKey, cfg.algorithm);  
    }

    /**
     * Encrypt one message: nonce || ciphertext (|| MAC if not AEAD)
     *
     * @param plaintext : data to encrypt
     * @param aad : associated data (authenticated, not encrypted)
     * @return encrypted : nonce, ciphertext and tag/MAC
     */
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws CryptoException
    {
        try
        {
            // random nonce, new for each message (never reuse a nonce with the same key)
            byte[] nonce = new byte[cfg.ivSize / 8];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(cfg.transformation());
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec(nonce));
            if (cfg.isAEAD())
                cipher.updateAAD(aad);                              
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] result = concat(nonce, ciphertext);

            if (!cfg.isAEAD())
                result = concat(result, hmac(aad, result));      // Encrypt-then-MAC
            return result;
        }
        catch (GeneralSecurityException e)
        {
            throw new CryptoException("Error encrypting", e);
        }
    }

    /**
     * Decrypt one message; any change to the data, nonce, tag/MAC or aad is detected
     *
     * @param encrypted : nonce, ciphertext and tag/MAC
     * @param aad : associated data used when encrypting
     * @return plaintext : decrypted data
     */
    public byte[] decrypt(byte[] encrypted, byte[] aad) throws CryptoException
    {
        try
        {
            byte[] data = encrypted;

            if (!cfg.isAEAD())                                   // verify the MAC before decrypting
            {
                int macLen = Mac.getInstance(cfg.macJavaName()).getMacLength();
                if (encrypted.length < macLen)
                    throw new CryptoException("Message integrity/authenticity check failed");
                data = new byte[encrypted.length - macLen];
                byte[] receivedMac = new byte[macLen];
                System.arraycopy(encrypted, 0, data, 0, data.length);
                System.arraycopy(encrypted, data.length, receivedMac, 0, macLen);
                if (!verify(aad, data, receivedMac))
                    throw new CryptoException("Message integrity/authenticity check failed");
            }

            // split nonce || ciphertext  
            byte[] nonce = new byte[cfg.ivSize / 8];
            if (data.length < nonce.length)
                throw new CryptoException("Message integrity/authenticity check failed");
            byte[] ciphertext = new byte[data.length - nonce.length];
            System.arraycopy(data, 0, nonce, 0, nonce.length);
            System.arraycopy(data, nonce.length, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(cfg.transformation());
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec(nonce));
            if (cfg.isAEAD())
                cipher.updateAAD(aad);                               
            return cipher.doFinal(ciphertext);                       // AEAD: the tag is verified here
        }
        catch (GeneralSecurityException e)                           
        {
            throw new CryptoException("Message integrity/authenticity check failed");
        }
    }

    /**
     * Parameters for cipher.init, according to the mode
     *
     * @param nonce : nonce / IV of the message
     * @return spec : GCM/CCM (128-bit tag), ChaCha20 or IV parameters
     */
    private AlgorithmParameterSpec paramSpec(byte[] nonce)
    {
        String t = cfg.transformation();
        if (t.contains("/GCM/"))
            return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);       
        if (t.contains("/CCM/"))                                    
            return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);       // 128-bit tag (IvParameterSpec gives 64)
        if (t.equals("ChaCha20"))
            return new ChaCha20ParameterSpec(nonce, INITIAL_COUNTER);
        return new IvParameterSpec(nonce);  
    }

    /**
     * MAC (HMAC or CMAC) of aad || data with the MAC key
     *
     * @param aad : associated data
     * @param data : nonce || ciphertext
     * @return mac : the computed MAC
     */
    private byte[] hmac(byte[] aad, byte[] data) throws GeneralSecurityException
    {
        Mac mac = Mac.getInstance(cfg.macJavaName());
        mac.init(new SecretKeySpec(cfg.macKey, cfg.macJavaName()));
        mac.update(aad);
        return mac.doFinal(data);
    }

    /**
     * Verify a received MAC with a constant-time comparison
     *
     * @param aad : associated data
     * @param data : nonce || ciphertext
     * @param receivedMac : MAC received with the message
     * @return valid : true if the MAC is correct
     */
    private boolean verify(byte[] aad, byte[] data, byte[] receivedMac) throws GeneralSecurityException
    {
        byte[] expected = hmac(aad, data);
        return MessageDigest.isEqual(expected, receivedMac);
    }

    /**
     * Concatenate two byte arrays
     *
     * @param a : first array
     * @param b : second array
     * @return result : a || b
     */
    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}