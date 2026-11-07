/**
 * Metrics of the Secure Proxy, printed after each stream (one per browser request).
 *
 * Throughput = media bytes forwarded to the browser / time, from the end of the
 * handshake until the END is verified or the stream stops (1 kB = 1000 bytes).
 * With a pause between blocks, the time includes it.
 */
public class ProxyMetrics {

    private final String name, range;
    private long t0;                  // start time (ns)
    private int code = -1;            // HTTP status of the response
    private long asked = -1;          // Content-Length of the response
    private long fileSize = -1;       // size of the original file
    private long blocksForwarded = 0;
    private long mediaBytes = 0;

    /**
     * Create the metrics of one stream
     *
     * @param name : requested movie
     * @param range : Range header of the browser, or null
     */
    public ProxyMetrics(String name, String range) {
        this.name = name;
        this.range = range;
    }

    /**
     * Mark the start of the stream (after the handshake)
     */
    public void start() {
        t0 = System.nanoTime();
    }

    /**
     * Store the HTTP status and headers sent by the server
     *
     * @param code : HTTP status code
     * @param contentLength : Content-Length of the response
     * @param contentRange : Content-Range of the response, or null
     */
    public void response(int code, long contentLength, String contentRange) {
        this.code = code;
        this.asked = contentLength;
        if (contentRange != null && contentRange.contains("/")) {            // "bytes start-end/size"
            fileSize = Long.parseLong(contentRange.substring(contentRange.indexOf('/') + 1).trim());
        } else if (code == 200) {
            fileSize = contentLength;
        }
    }

    /**
     * Count one decrypted block forwarded to the browser
     *
     * @param n : size of the block in bytes
     */
    public void forwarded(int n) {
        blocksForwarded++;
        mediaBytes += n;
    }

    /**
     * Print the metrics of the stream
     *
     * @param ch : secure channel (bytes received on the network)
     * @param sin : secure input stream (encrypted blocks received), or null
     * @param end : how the stream ended (COMPLETE, INCOMPLETE or ERROR)
     */
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