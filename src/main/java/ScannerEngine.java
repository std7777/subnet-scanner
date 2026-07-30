import java.net.*;
import java.time.Instant;
import java.util.concurrent.*;
import java.util.*;

public class ScannerEngine {

    private final ScanConfig config;

    private final ThreadPoolExecutor executor;
    private final SimpleRateLimiter rateLimiter;

    private final ConcurrentHashMap<String, ConcurrentHashMap<Integer, ScanResult>> results = new ConcurrentHashMap<>();
    private final Set<String> aliveHosts = ConcurrentHashMap.newKeySet();

    public ScannerEngine(ScanConfig config) {
        this.config = config;

        // Increased worker threads to 300
        this.executor = new ThreadPoolExecutor(
                300,   // corePoolSize
                300,   // maximumPoolSize
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(5000),
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        // Increased rate limit to 1000/sec (capped at 2000 by design)
        int configuredRate = Math.min(1000, 2000);
        this.rateLimiter = new SimpleRateLimiter(configuredRate);
    }

    public ScanReport execute() {
        try {
            submitJobs();
            executor.shutdown();

            if (!executor.awaitTermination(7, TimeUnit.DAYS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        } finally {
            if (!executor.isShutdown()) {
                executor.shutdownNow();
            }
            rateLimiter.close();
        }

        return buildReport();
    }

    private void submitJobs() {
        long base = ipToLong(config.networkAddress);
        long firstHostOffset = config.firstHostOffset();
        long scanHostCount = config.scanHostCount();
        long endHostOffset = firstHostOffset + scanHostCount;

        for (long i = firstHostOffset; i < endHostOffset; i++) {
            long ipLong = base + i;
            String ip = longToIp(ipLong);

            for (int port = config.startPort; port <= config.endPort; port++) {
                executor.execute(new ScanTask(ip, port));
            }
        }
    }

    private ScanReport buildReport() {
        List<HostReport> hostReports = new ArrayList<>();

        List<String> sortedHosts = new ArrayList<>(aliveHosts);
        sortedHosts.sort(Comparator.comparingLong(this::ipToLong));

        for (String host : sortedHosts) {
            Map<Integer, ScanResult> portMap =
                    results.getOrDefault(host, new ConcurrentHashMap<>());

            List<ScanResult> sortedPorts =
                    new ArrayList<>(portMap.values());

            sortedPorts.sort(Comparator.comparingInt(r -> r.port));

            hostReports.add(new HostReport(host, sortedPorts));
        }

        return new ScanReport(Instant.now().toString(), hostReports);
    }

    private class ScanTask implements Runnable {

        private final String ip;
        private final int port;

        ScanTask(String ip, int port) {
            this.ip = ip;
            this.port = port;
        }

        @Override
        public void run() {
            try {
                attempt();
            } catch (Exception e) {
                System.err.println("Worker error: " + e.getMessage());
            }
        }

        private void attempt() {
            int attempts = 0;

            while (attempts < 2) {
                attempts++;

                try (Socket socket = new Socket()) {

                    // Rate limit applied immediately before connect
                    if (!rateLimiter.acquire()) {
                        return;
                    }

                    socket.connect(
                            new InetSocketAddress(ip, port),
                            config.connectTimeoutMs
                    );

                    socket.setSoTimeout(config.readTimeoutMs);

                    // If we reach here, connection succeeded
                    aliveHosts.add(ip);

                    String banner = readBanner(socket);
                    String service = ServiceMapper.map(port);

                    results
                        .computeIfAbsent(ip, k -> new ConcurrentHashMap<>())
                        .put(port, new ScanResult(port, service, banner));

                    System.err.println("Open port: " + ip + ":" + port);
                    return;

                } catch (SocketTimeoutException e) {
                    // Retry only on connect timeout
                    if (attempts >= 2) return;

                } catch (ConnectException e) {
                    // Connection refused → host alive
                    aliveHosts.add(ip);
                    return;

                } catch (Exception e) {
                    // Other errors → ignore and continue
                    return;
                }
            }
        }

        private String readBanner(Socket socket) {
            try {
                byte[] buffer = new byte[256];
                int read = socket.getInputStream().read(buffer);
                if (read > 0) {
                    return new String(buffer, 0, read).trim();
                }
            } catch (Exception ignored) {}
            return null;
        }
    }

    private long ipToLong(String ip) {
        try {
            return ipToLong(InetAddress.getByName(ip));
        } catch (Exception e) {
            return 0;
        }
    }

    private long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result = (result << 8) | (octet & 0xff);
        }
        return result;
    }

    private String longToIp(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 8) & 0xff,
                ip & 0xff);
    }
}
