package io.github.tajaddin.threat.ingest;

import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Synthetic load for demos and the load runner. Events go through the same accept() path as the
 * HTTP endpoint, so the measured rate is the pipeline's rate from ingest onwards (minus HTTP
 * parsing).
 */
@RestController
@RequestMapping("/api/generate")
@Validated
@Tag(name = "generate", description = "Synthetic traffic generator")
public class GeneratorController {
  private static final Logger log = LoggerFactory.getLogger(GeneratorController.class);

  public record Request(
      @Min(1) @Max(50_000) int eventsPerSecond,
      @Min(1) @Max(3600) int seconds,
      @DecimalMin("0.0") @DecimalMax("1.0") double attackShare,
      Long seed) {}

  public record Status(
      boolean running,
      long produced,
      long duplicates,
      Instant startedAt,
      Instant finishedAt,
      double achievedPerSecond) {}

  private final IngestService ingest;
  private final ExecutorService executor =
      Executors.newSingleThreadExecutor(r -> new Thread(r, "generator"));
  private final AtomicBoolean running = new AtomicBoolean();
  private final AtomicLong produced = new AtomicLong();
  private final AtomicLong duplicates = new AtomicLong();
  private volatile Instant startedAt;
  private volatile Instant finishedAt;

  public GeneratorController(IngestService ingest) {
    this.ingest = ingest;
  }

  @PostMapping
  @Operation(summary = "Start generating events at a target rate for a duration")
  public ResponseEntity<?> start(@RequestBody @jakarta.validation.Valid Request req) {
    if (!running.compareAndSet(false, true)) {
      return ResponseEntity.status(409)
          .body(Map.of("error", "a generation run is already in progress"));
    }
    produced.set(0);
    duplicates.set(0);
    startedAt = Instant.now();
    finishedAt = null;
    executor.submit(() -> run(req));
    return ResponseEntity.accepted()
        .body(
            Map.of(
                "status",
                "started",
                "eventsPerSecond",
                req.eventsPerSecond(),
                "seconds",
                req.seconds()));
  }

  @GetMapping
  public Status status() {
    Instant end = finishedAt != null ? finishedAt : Instant.now();
    double secs =
        startedAt == null
            ? 0
            : Math.max(0.001, Duration.between(startedAt, end).toMillis() / 1000.0);
    return new Status(
        running.get(),
        produced.get(),
        duplicates.get(),
        startedAt,
        finishedAt,
        startedAt == null ? 0 : produced.get() / secs);
  }

  private void run(Request req) {
    SyntheticEvents synth =
        new SyntheticEvents(
            req.seed() != null ? req.seed() : System.nanoTime(), req.attackShare(), "generator");
    int batch = Math.max(1, Math.min(500, req.eventsPerSecond() / 10));
    long intervalNanos = (long) (1_000_000_000.0 * batch / req.eventsPerSecond());
    long end = System.nanoTime() + req.seconds() * 1_000_000_000L;
    long next = System.nanoTime();
    try {
      while (System.nanoTime() < end) {
        List<Event> events = synth.batch(Instant.now(), batch);
        try {
          IngestService.Result r = ingest.accept(events);
          produced.addAndGet(r.accepted());
          duplicates.addAndGet(r.duplicates());
        } catch (IngestService.ProducerBackpressureException ex) {
          log.warn("generator backpressure: {}", ex.getMessage());
          Thread.sleep(200);
        }
        next += intervalNanos;
        long sleep = next - System.nanoTime();
        if (sleep > 0) {
          Thread.sleep(sleep / 1_000_000, (int) (sleep % 1_000_000));
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException ex) {
      log.error("generator stopped: {}", ex.getMessage(), ex);
    } finally {
      finishedAt = Instant.now();
      running.set(false);
      log.info(
          "generator finished produced={} duplicates={} seconds={}",
          produced.get(),
          duplicates.get(),
          Duration.between(startedAt, finishedAt).toSeconds());
    }
  }
}
