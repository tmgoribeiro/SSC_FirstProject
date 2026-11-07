/**
 * Helper functions: hexadecimal, conversion between long and bytes, concatenation
 */
public class Utils
{
    private static String	digits = "0123456789abcdef";

    /**
     * Return string hexadecimal from byte array of certain size
     *
     * @param data : bytes to convert
     * @param length : nr of bytes in data block to be converted
     * @return hex : hexadecimal representation of data
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
     * Return string hexadecimal from byte array
     *
     * @param data : bytes to convert
     * @return hex : hexadecimal representation of data
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    /**
     * Convert a number to 8 bytes, most significant byte first
     *
     * @param number : number to convert (ex. a sequence number)
     * @return bytes : 8-byte representation
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
     * Convert 8 bytes back to a number (inverse of longToBytes)
     *
     * @param bytes : array with the 8 bytes
     * @param offset : position of the first byte
     * @return number : the number
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
     * Concatenate two byte arrays
     *
     * @param a : first array
     * @param b : second array
     * @return result : a || b
     */
    public static byte[] concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}