/**
 * Material/Labs for SRSC 21/22, Sem-1
 * hj
 **/

// GenerateKey.java

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class GenerateKey {

  /**
   * main()
   * Use: java GenerateKey <algorithm> <keysize in bits>
   *   ex: java GenerateKey AES 256         (Lab 2)
   *       java GenerateKey ChaCha20 256    (Lab 3.1 / 3.2)
   *       java GenerateKey HmacSHA256 256  (MAC key)
   *       java GenerateKey RANDOM 256      (SecureRandom bytes, as HmacExample)
   */
  public static void main(String[] args) throws Exception {

    if (args.length != 2) {
      System.out.println("Use: java GenerateKey <algorithm> <keysize in bits>");
      System.out.println("ex: java GenerateKey AES 256");
      System.out.println("    java GenerateKey ChaCha20 256");
      System.out.println("    java GenerateKey HmacSHA256 256");
      System.out.println("    java GenerateKey RANDOM 256");
      System.exit(-1);
    }

    String ALGORITHM = args[0];
    int KEYSIZE = Integer.parseInt(args[1]);
    byte[] keyBytes;

    if (ALGORITHM.equalsIgnoreCase("RANDOM")) {
      // As in HmacExample (Lab 3.2): byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
      keyBytes = new byte[KEYSIZE / 8];
      new SecureRandom().nextBytes(keyBytes);
    }
    else {
      // Key generation for the chosen Alg. (as in Lab 2 GenerateKey)
      KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
      kg.init(KEYSIZE);
      SecretKey key = kg.generateKey();
      keyBytes = key.getEncoded();
    }

    // Print it (as hjCipherTest): copy the SAME value to both config files
    System.out.println("----------------------------------------------");
    System.out.println("Key " + ALGORITHM + " with " + KEYSIZE + " bits");
    System.out.println("Key in Hex:\n" + Utils.toHex(keyBytes));
    System.out.println("Key in Base64:\n" + Base64.getEncoder().encodeToString(keyBytes));
    System.out.println("Key Size in Bytes: " + keyBytes.length);
    System.out.println("----------------------------------------------");
  }
}





