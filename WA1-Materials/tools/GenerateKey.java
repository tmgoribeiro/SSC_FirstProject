/**
 * Material/Labs for SRSC 21/22, Sem-1
 * 
 **/

// GenerateKey.java

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Generates a random secret key and prints it in hexadecimal and Base64
 *
 * Use: java GenerateKey <algorithm> <keysize in bits>
 */
public class GenerateKey {

  /**
   * Generate one key with KeyGenerator, or random bytes with RANDOM
   *
   * @param args : algorithm (ex. AES, ChaCha20, HmacSHA256 or RANDOM) and key size in bits
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
      // random bytes from SecureRandom
      keyBytes = new byte[KEYSIZE / 8];
      new SecureRandom().nextBytes(keyBytes);
    }
    else {
      // key generator of the chosen algorithm
      KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
      kg.init(KEYSIZE);
      SecretKey key = kg.generateKey();
      keyBytes = key.getEncoded();
    }

    // print it: copy the SAME value to both config files (proxy and server)
    System.out.println("----------------------------------------------");
    System.out.println("Key " + ALGORITHM + " with " + KEYSIZE + " bits");
    System.out.println("Key in Hex:\n" + Utils.toHex(keyBytes));
    System.out.println("Key in Base64:\n" + Base64.getEncoder().encodeToString(keyBytes));
    System.out.println("Key Size in Bytes: " + keyBytes.length);
    System.out.println("----------------------------------------------");
  }
}