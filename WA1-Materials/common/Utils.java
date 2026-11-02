/**
 * Auxiliar
 * Some conversion functions
 *
 * toHex: as Lab 2 common/Utils.java
 * longToBytes / bytesToLong: as Lab 3.1 Utils.createCtrIvForAES, which puts the
 *     message number in the IV byte by byte:  ivBytes[0] = (byte)(messageNumber >> 24); ...
 * concat: as Lab 3.2 SimpleGCMExample ("prepend nonce to ciphertext"), with System.arraycopy
 */
public class Utils
{
    private static String	digits = "0123456789abcdef";

    /**
     * Return string hexadecimal from byte array of certain size
     *
     * @param data : bytes to convert
     * @param length : nr of bytes in data block to be converted
     * @return  hex : hexadecimal representation of data
     */

   public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();

        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return data in byte array from string hexadecimal
     *
     * @param data : bytes to be converted
     * @return : hexadecimal repersentatin of data
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    /**
     * Number (e.g. a sequence number) -> 8 bytes, most significant byte first,
     * as createCtrIvForAES (Lab 3.1) does with the message number.
     */
    public static byte[] longToBytes(long number)
    {
        byte[] bytes = new byte[8];
        for (int i = 0; i != 8; i++)
        {
            bytes[i] = (byte)(number >> (56 - 8 * i));
        }
        return bytes;
    }

    /**
     * 8 bytes starting at offset -> number (the inverse of longToBytes).
     */
    public static long bytesToLong(byte[] bytes, int offset)
    {
        long number = 0;
        for (int i = 0; i != 8; i++)
        {
            number = (number << 8) | (bytes[offset + i] & 0xff);
        }
        return number;
    }

    /**
     * a || b, as SimpleGCMExample joins nonce || ciphertext:
     *   byte[] result = new byte[nonce.length + ciphertext.length];
     *   System.arraycopy(nonce, 0, result, 0, nonce.length);
     *   System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
     */
    public static byte[] concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}