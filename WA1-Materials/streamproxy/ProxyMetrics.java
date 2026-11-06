/**
 * Metrics of the Secure Proxy (WA1 section 4), printed after each stream
 * (each GET /video/... of the browser is one stream from the Secure Stream Server).
 *
 * Throughput methodology: media bytes forwarded to the browser / time, where
 * time goes from the end of the handshake (System.nanoTime) until the END
 * (Type 5) is verified or the stream stops. 1 kB = 1000 bytes.
 * With a pause between blocks (Thread.sleep in the relay loop) the time includes it.
 */
public class ProxyMetrics {

    private final String name, range;
    private long t0;
    private int code = -1;
    private long asked = -1;          // Content-Length of the response
    private long fileSize = -1;       // size of the original file
    private long blocksForwarded = 0;
    private long mediaBytes = 0;

    public ProxyMetrics(String name, String range) {
        this.name = name;
        this.range = range;
    }

    /** After the handshake: the stream starts. */
    public void start() {
        t0 = System.nanoTime();
    }

    /** HTTP status and headers sent by the Stream Server (inside the first Type 4 block). */
    public void response(int code, long contentLength, String contentRange) {
        this.code = code;
        this.asked = contentLength;
        if (contentRange != null && contentRange.contains("/")) {            // "bytes start-end/size"
            fileSize = Long.parseLong(contentRange.substring(contentRange.indexOf('/') + 1).trim());
        } else if (code == 200) {
            fileSize = contentLength;
        }
    }

    /** One decrypted block forwarded to the browser. */
    public void forwarded(int n) {
        blocksForwarded++;
        mediaBytes += n;
    }

    public void print(SecureChannel ch, SecureInputStream sin, String end) {
        double s = t0 == 0 ? 0 : (System.nanoTime() - t0) / 1e9;
        System.out.println("[metrics] " + name + (range == null ? "" : "  (Range " + range + ")")
                + "  HTTP " + code + "  " + end);
        System.out.println("   encrypted blocks received : " + (sin == null ? 0 : sin.blocksReceived));
        System.out.println("   decrypted blocks forwarded: " + blocksForwarded);
        System.out.println("   media bytes forwarded     : " + mediaBytes + "  (asked " + asked + ", original file " + fileSize + ")");
        System.out.println("   bytes received (network)  : " + ch.bytesReceived);
        System.out.printf("   throughput                : %.1f kB/s  (%d bytes in %.3f s)%n",
                s == 0 ? 0 : mediaBytes / 1000.0 / s, mediaBytes, s);
    }
}