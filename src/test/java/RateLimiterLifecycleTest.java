import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterLifecycleTest {

    @Test
    void rejectsInvalidRate() {
        assertThrows(IllegalArgumentException.class, () -> new SimpleRateLimiter(0));
    }

    @Test
    void preservesInterruption() throws Exception {
        SimpleRateLimiter limiter = new SimpleRateLimiter(1);
        try {
            assertTrue(limiter.acquire(), "Initial permit should be available");

            AtomicBoolean acquired = new AtomicBoolean(true);
            AtomicBoolean interrupted = new AtomicBoolean(false);

            Thread waiter = new Thread(() -> {
                acquired.set(limiter.acquire());
                interrupted.set(Thread.currentThread().isInterrupted());
            });

            waiter.start();
            waitUntilBlocked(waiter);
            waiter.interrupt();
            waiter.join(1_000);

            assertFalse(waiter.isAlive(), "Interrupted permit waiter should stop");
            assertFalse(acquired.get(), "Interrupted permit waiter must not acquire");
            assertTrue(interrupted.get(), "Interrupted status should be preserved");
        } finally {
            limiter.close();
        }
    }

    @Test
    void closeStopsPermitRefill() throws Exception {
        SimpleRateLimiter limiter = new SimpleRateLimiter(1);
        assertTrue(limiter.acquire(), "Initial permit should be available");
        limiter.close();

        AtomicBoolean acquired = new AtomicBoolean(true);
        Thread waiter = new Thread(() -> acquired.set(limiter.acquire()));

        waiter.start();
        Thread.sleep(1_200);

        assertTrue(waiter.isAlive(), "Closed limiter must not refill permits");

        waiter.interrupt();
        waiter.join(1_000);

        assertFalse(waiter.isAlive(), "Interrupted permit waiter should stop");
        assertFalse(acquired.get(), "No permit should be acquired after close");
    }

    @Test
    void closeIsIdempotent() {
        SimpleRateLimiter limiter = new SimpleRateLimiter(1);
        limiter.close();
        limiter.close();
    }

    private static void waitUntilBlocked(Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + 1_000_000_000L;

        while (thread.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }

        assertTrue(thread.getState() == Thread.State.WAITING,
                "Permit waiter did not block within the expected time");
    }
}
