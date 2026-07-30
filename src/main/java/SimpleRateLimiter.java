import java.util.concurrent.Semaphore;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SimpleRateLimiter implements AutoCloseable {

    private final Semaphore semaphore;
    private final ScheduledExecutorService scheduler;

    public SimpleRateLimiter(int permitsPerSecond) {
        if (permitsPerSecond <= 0) {
            throw new IllegalArgumentException("permitsPerSecond must be greater than zero");
        }

        this.semaphore = new Semaphore(permitsPerSecond);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "scanner-rate-limiter");
            thread.setDaemon(true);
            return thread;
        });

        scheduler.scheduleAtFixedRate(() -> {
            int deficit = permitsPerSecond - semaphore.availablePermits();
            if (deficit > 0) {
                semaphore.release(deficit);
            }
        }, 1, 1, TimeUnit.SECONDS);
    }

    public boolean acquire() {
        try {
            semaphore.acquire();
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }
}
