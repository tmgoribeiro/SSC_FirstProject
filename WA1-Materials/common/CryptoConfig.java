import java.io.File;
import java.util.Base64;
import java.util.HexFormat;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Cryptographic configuration of the Secure Proxy / Secure Stream Server,
 */

public class CryptoConfig
{

    static { Security.addProvider(new BouncyCastleProvider());}
    public String algorithm;     // ex: AES, ChaCha20, RC6
    public String mode;          // ex: GCM, CBC, CTR, Poly1305, or null
    public byte[] iv;            // IV value, or null
    public int    ivSize;        // IV size in bits, or 0
    public String padding;       // ex: PKCS5Padding, NoPadding, or null

    public String macAlgorithm;  // ex: HMAC-SHA256, or null

    public byte[] symKey;
    public int    symKeySize;    // bits
    public byte[] macKey;        // or null
    public int    macKeySize;    // bits, or 0

    /**
     * Read and validate a configuration file (proxycrypto.config / sservercrypto.config).
     */
    public static CryptoConfig load(String fileName) throws CryptoException
    {
        try
        {
            Document doc = secureParser().parse(new File(fileName));
            Element root = doc.getDocumentElement();     // <ProxyCryptoConfig> or <SServerCryptoConfig>
            CryptoConfig c = new CryptoConfig();

            // <SymCipherSuite>
            Element sym = child(root, "SymCipherSuite");
            c.algorithm = text(sym, "Algorithm");
            c.mode      = text(sym, "Mode");
            c.padding   = text(sym, "Padding");
            Element ivElem = child(sym, "InitializationVector");
            String ivText   = text(ivElem, "IV");
            String ivSizeTx = text(ivElem, "IVSIZE");
            c.ivSize = ivSizeTx == null ? 0 : Integer.parseInt(ivSizeTx);
            c.iv     = ivText == null ? null : decode(ivText, c.ivSize, "IV");

            // <MACsuite>
            c.macAlgorithm = text(child(root, "MACsuite"), "Algorithm");

            // <ConfiguredKeys>
            Element keys = child(root, "ConfiguredKeys");
            Element sk = child(keys, "SymmetricKey");
            c.symKeySize = Integer.parseInt(required(text(sk, "Keysize"), "Keysize"));
            c.symKey     = decode(required(text(sk, "SKey"), "SKey"), c.symKeySize, "SKey");

            Element mk = child(keys, "MACKey");
            String mkSize = text(mk, "MacKeySize");
            String mkText = text(mk, "MacKey");
            c.macKeySize = mkSize == null ? 0 : Integer.parseInt(mkSize);
            c.macKey     = mkText == null ? null : decode(mkText, c.macKeySize, "MacKey");

            c.validate();        
            return c;
        }
        catch (CryptoException e)
        {
            throw e;             // already has a clear message
        }
        catch (Exception e)   
        {
            throw new CryptoException("Invalid config file " + fileName + ": " + e.getMessage(), e);
        }
    }


    /**
     * True for AEAD modes
     */
    public boolean isAEAD()
    {
        return "GCM".equalsIgnoreCase(mode) || "CCM".equalsIgnoreCase(mode)
            || "Poly1305".equalsIgnoreCase(mode);
    }

    /**
     * The JCE transformation for Cipher.getInstance()
     */
    public String transformation()
    {
        if ("ChaCha20".equalsIgnoreCase(algorithm))
            return "Poly1305".equalsIgnoreCase(mode) ? "ChaCha20-Poly1305" : "ChaCha20";
        return algorithm + "/" + mode + "/" + (padding == null ? "NoPadding" : padding);
    }

    /**
     * Java name of the configured MAC, for Mac.getInstance()
     * (null if no MAC is configured)
     */
    public String macJavaName()
    {
        if (macAlgorithm == null) return null;
        String s = macAlgorithm.trim();
        if (s.equalsIgnoreCase("AES-CMAC") || s.equalsIgnoreCase("CMAC")) return "AESCMAC";
        if (s.regionMatches(true, 0, "HMAC-", 0, 5)) s = "Hmac" + s.substring(5);
        else if (s.regionMatches(true, 0, "HMAC", 0, 4)) s = "Hmac" + s.substring(4);
        return s.replaceAll("(?i)SHA-(1|224|256|384|512)$", "SHA$1");
    }

     /**
     * Proposed Cryptographic Configuration (PCC) sent in handshake message type 1,
     * in the format (algorithm/mode/ivSize/padding).
     */
    public String proposal()
    {
        return n(algorithm) + "/" + n(mode) + "/" + (ivSize == 0 ? "NULL" : ivSize)
             + "/" + n(padding);
    }

    /**
     * Refuse configurations that cannot give the guarantees required by the
     * assignment (the threat model asks to consider incorrect configurations).
     */
    private void validate() throws CryptoException
    {
        if (algorithm == null)
            throw new CryptoException("<Algorithm> is required");
        if (symKeySize != 128 && symKeySize != 192 && symKeySize != 256)   // WA1 2.2.2: "128, 192 or 256 bits"
            throw new CryptoException("<Keysize> must be 128, 192 or 256 bits");
        if ("ECB".equalsIgnoreCase(mode))
            throw new CryptoException("ECB is not allowed: identical blocks give identical ciphertext");
        if ("ChaCha20".equalsIgnoreCase(algorithm) && symKeySize != 256)   // ChaCha20 only has 256-bit keys
            throw new CryptoException("ChaCha20 needs a 256-bit key (<Keysize> 256)");
        if (!isAEAD() && macAlgorithm == null)
            throw new CryptoException(transformation() + " gives no integrity: use an AEAD mode or configure a MAC");
        if (macAlgorithm != null && macKey == null)
            throw new CryptoException("<MACsuite> is configured but <MacKey> is NULL");
        if (macKey != null && java.util.Arrays.equals(macKey, symKey))
            throw new CryptoException("The MAC key must be different from the encryption key");
        if ("CCM".equalsIgnoreCase(mode) && (ivSize < 56 || ivSize > 104 || ivSize % 8 != 0))   // WA1 7.3
            throw new CryptoException("CCM needs a nonce of 7 to 13 bytes (<IVSIZE> 56..104)");
        if (mode != null && ivSize == 0)
            throw new CryptoException("Mode " + mode + " needs an <IVSIZE>");
    }
    // ------------------------------------------------------------- helpers

    /** XML parser protected against XXE (no DOCTYPE / external entities in the config). */
    private static DocumentBuilder secureParser() throws Exception
    {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setExpandEntityReferences(false);
        return f.newDocumentBuilder();
    }

    /**
     * First element named <tag> inside parent, IGNORING upper/lower case:
     * the assignment writes <MACsuite> and </MACSuite>, and the reference test
     * writes <IVSIZE>, so <MACSuite>, <MACsuite>, <IVSIZE>, <IVSize> are all accepted.
     */
    private static Element child(Element parent, String tag) throws CryptoException
    {
        NodeList l = parent.getElementsByTagName("*");          // all descendants
        for (int i = 0; i < l.getLength(); i++)
            if (l.item(i).getNodeName().equalsIgnoreCase(tag))
                return (Element) l.item(i);
        throw new CryptoException("Missing <" + tag + "> in config file");
    }

    /** Text of an element; "NULL" or empty -> null. */
    private static String text(Element parent, String tag) throws CryptoException
    {
        String v = child(parent, tag).getTextContent().trim();
        return (v.isEmpty() || v.equalsIgnoreCase("NULL")) ? null : v;
    }

    private static String required(String v, String tag) throws CryptoException
    {
        if (v == null) throw new CryptoException("<" + tag + "> cannot be NULL");
        return v;
    }

    /** Key/IV in hexadecimal or Base64; checks that the size matches the declared size. */
    private static byte[] decode(String s, int bits, String tag) throws CryptoException
    {
        byte[] b;
        if (s.matches("([0-9a-fA-F]{2})+"))   // only hex digits -> hexadecimal
            b = HexFormat.of().parseHex(s);   // as in Lab 3.2 AesCmacExample
        else
        {
            try { b = Base64.getDecoder().decode(s); }
            catch (IllegalArgumentException e)
            { throw new CryptoException("<" + tag + "> is neither hex nor Base64"); }
        }
        if (b.length * 8 != bits)
            throw new CryptoException("<" + tag + "> has " + b.length * 8 + " bits, but its size says " + bits);
        return b;
    }

    private static String n(String s)
    {
        return s == null ? "NULL" : s;
    }
}