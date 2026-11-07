import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Downloads several movies through the proxies, first one at a time and then all together, checking each one with SHA-256
 */
public class ConcurrencyTest
{
    static ExecutorService pool = Executors.newCachedThreadPool();

    /**
     * Run the sequential and the concurrent downloads and print the results
     *
     * @param args : media folder and one "port:movie" per client
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length < 2)
        {
            System.out.println("Use: java ConcurrencyTest <mediaDir> <port:movie> [<port:movie> ...]");
            System.exit(-1);
        }
        Path media = Paths.get(args[0]);
        List<String[]> clients = new ArrayList<>();
        for (int i = 1; i < args.length; i++)
            clients.add(args[i].split(":", 2));

        System.out.println("== Sequential: " + clients.size() + " downloads, one after the other");
        long t0 = System.nanoTime();
        List<String> seq = new ArrayList<>();
        for (int i = 0; i < clients.size(); i++)
            seq.add(download(i + 1, clients.get(i), media, null));
        double seqTime = (System.nanoTime() - t0) / 1e9;
        seq.forEach(System.out::println);
        System.out.printf("   total time: %.3f s%n%n", seqTime);

        System.out.println("== Concurrent: " + clients.size() + " downloads at the same time");
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> results = new ArrayList<>();
        for (int i = 0; i < clients.size(); i++)
        {
            final int id = i + 1;
            final String[] c = clients.get(i);
            results.add(pool.submit(() -> download(id, c, media, start)));
        }
        t0 = System.nanoTime();
        start.countDown();                                  // all start together
        int ok = 0;
        List<String> lines = new ArrayList<>();
        for (Future<String> f : results)
        {
            String line = f.get();
            lines.add(line);
            if (line.contains("hash OK")) ok++;
        }
        double conTime = (System.nanoTime() - t0) / 1e9;
        lines.forEach(System.out::println);
        System.out.printf("   total time: %.3f s  (sequential %.3f s, speed-up %.2fx)%n", conTime, seqTime, seqTime / conTime);

        System.out.println("======================================");
        System.out.println(ok == clients.size() ? "ALL " + ok + " CONCURRENT STREAMS OK" : (clients.size() - ok) + " STREAM(S) FAILED");
        pool.shutdownNow();
        System.exit(ok == clients.size() ? 0 : 1);
    }

    /**
     * Download one movie from a proxy and compare it with the original file
     *
     * @param id : client number
     * @param client : proxy port and movie name
     * @param media : folder with the original movies
     * @param start : latch to start all clients together, or null
     * @return line : result of the client (bytes, time, kB/s, hash OK or not)
     */
    static String download(int id, String[] client, Path media, CountDownLatch start)
    {
        int port = Integer.parseInt(client[0]);
        String movie = client[1];
        try
        {
            if (start != null) start.await();
            long t0 = System.nanoTime();
            try (Socket s = new Socket("localhost", port))
            {
                OutputStream out = s.getOutputStream();
                out.write(("GET /video/" + movie + " HTTP/1.1\r\nHost: localhost:" + port
                           + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();

                InputStream in = s.getInputStream();
                String status = readLine(in);
                while (!readLine(in).isEmpty()) { }            // skip the headers

                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] buf = new byte[1024];
                long bytes = 0;
                int n;
                while ((n = in.read(buf)) != -1)
                {
                    sha.update(buf, 0, n);
                    bytes += n;
                }
                double sec = (System.nanoTime() - t0) / 1e9;
                byte[] original = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(media.resolve(movie)));
                boolean same = MessageDigest.isEqual(sha.digest(), original);
                return String.format("   client %d  port %d  %-15s %-20s %10d bytes  %7.3f s  %9.1f kB/s  %s",
                                     id, port, movie, status, bytes, sec, bytes / 1000.0 / sec,
                                     same ? "hash OK" : "HASH DIFFERENT");
            }
        }
        catch (Exception e)
        {
            return "   client " + id + "  port " + port + "  " + movie + "  FAILED: " + e;
        }
    }

    /**
     * Read one CRLF-terminated line, byte by byte
     *
     * @param in : stream to read from
     * @return line : the line without CRLF
     */
    static String readLine(InputStream in) throws IOException
    {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int prev = -1, cur;
        while ((cur = in.read()) != -1)
        {
            if (prev == '\r' && cur == '\n')
            {
                byte[] b = line.toByteArray();
                return new String(b, 0, b.length - 1, StandardCharsets.US_ASCII);
            }
            line.write(cur);
            prev = cur;
        }
        return line.toString(StandardCharsets.US_ASCII);
    }
}