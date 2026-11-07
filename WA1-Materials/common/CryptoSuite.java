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
 * Encryption / decryption of ONE message (one block of the stream), with the
 * cryptographic configuration read from the config file (WA1 2.2.4: not hard-coded).
 *
 * Format of an encrypted message:
 *   AEAD (AES/GCM, ChaCha20-Poly1305):   nonce || ciphertext+tag
 *   Others (AES/CTR, AES/CBC, ChaCha20): nonce || ciphertext || HMAC_K2(aad || nonce || ciphertext)
 *                                        (Encrypt-then-MAC, Lab 3.2: Ek1(M) || MACk2(Ek1(M)))
 */
public class CryptoSuite
{
    private static final int GCM_TAG_LENGTH = 128;   // bits, as SimpleGCMExample / AESGCM
    private static final int INITIAL_COUNTER = 0;    // as ChaCha20.java (Lab 3.1)

    private final CryptoConfig cfg;
    private final SecretKey key;                     // K1: encryption key  (<SKey>)
    private final SecureRandom random = new SecureRandom();

    public CryptoSuite(CryptoConfig cfg)
    {
        this.cfg = cfg;
        this.key = new SecretKeySpec(cfg.symKey, cfg.algorithm);   // as KeyRing.readSecretKey()
    }

    /**
     * Encrypt one message (as SimpleGCMExample.encrypt).
     * aad: data sent in clear (e.g. the header) that must also be protected.
     */
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws CryptoException
    {
        try
        {
            // random nonce, NEW for each message ("Never reuse an IV/key pair", AESGCM)
            byte[] nonce = new byte[cfg.ivSize / 8];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(cfg.transformation());
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec(nonce));
            if (cfg.isAEAD())
                cipher.updateAAD(aad);                               // as SimpleCCMExample
            byte[] ciphertext = cipher.doFinal(plaintext);

            // prepend nonce to ciphertext (needed for decryption)  -- SimpleGCMExample
            byte[] result = concat(nonce, ciphertext);

            // not AEAD: Encrypt-then-MAC with the second key (K2)
            if (!cfg.isAEAD())
                result = concat(result, hmac(aad, result));
            return result;
        }
        catch (GeneralSecurityException e)
        {
            throw new CryptoException("Error encrypting", e);
        }
    }

        /**
     * Decrypt one message (as SimpleGCMExample.decrypt).
     * Any modification of the message, its nonce, its tag/MAC or the aad is detected:
     * always the same error message, to give no hints to an attacker.
     */
    public byte[] decrypt(byte[] encrypted, byte[] aad) throws CryptoException
    {
        try
        {
            byte[] data = encrypted;

            // not AEAD: check the HMAC FIRST, and only then decrypt
            if (!cfg.isAEAD())
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

            // split nonce || ciphertext  -- SimpleGCMExample
            byte[] nonce = new byte[cfg.ivSize / 8];
            if (data.length < nonce.length)
                throw new CryptoException("Message integrity/authenticity check failed");
            byte[] ciphertext = new byte[data.length - nonce.length];
            System.arraycopy(data, 0, nonce, 0, nonce.length);
            System.arraycopy(data, nonce.length, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(cfg.transformation());
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec(nonce));
            if (cfg.isAEAD())
                cipher.updateAAD(aad);                               // must match encrypt side
            return cipher.doFinal(ciphertext);                       // AEAD: Java verifies the tag
        }
        catch (GeneralSecurityException e)                           // e.g. AEADBadTagException
        {
            throw new CryptoException("Message integrity/authenticity check failed");
        }
    }


    /** Parameters for cipher.init, as in each Lab example. */
    private AlgorithmParameterSpec paramSpec(byte[] nonce)
    {
        String t = cfg.transformation();
        if (t.contains("/GCM/"))
            return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);       // SimpleGCMExample
        if (t.contains("/CCM/"))                                    
            return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);       // its TAG_LENGTH = 128 (IvParameterSpec gives 64)
        if (t.equals("ChaCha20"))
            return new ChaCha20ParameterSpec(nonce, INITIAL_COUNTER); // ChaCha20.java
        return new IvParameterSpec(nonce);   // CBC, CTR (SimpleCBC/CTRExample), ChaCha20-Poly1305
    }

    /** HMAC of aad || data with the MAC key K2 (as HmacExample.hmac). */
    private byte[] hmac(byte[] aad, byte[] data) throws GeneralSecurityException
    {
        Mac mac = Mac.getInstance(cfg.macJavaName());
        mac.init(new SecretKeySpec(cfg.macKey, cfg.macJavaName()));
        mac.update(aad);
        return mac.doFinal(data);
    }

    /** Verify a received HMAC using a constant-time comparison (as HmacExample.verify). */
    private boolean verify(byte[] aad, byte[] data, byte[] receivedMac) throws GeneralSecurityException
    {
        byte[] expected = hmac(aad, data);
        return MessageDigest.isEqual(expected, receivedMac);
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}