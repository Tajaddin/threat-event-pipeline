package io.github.tajaddin.threat.ingest;

import io.github.tajaddin.threat.common.Event;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/events")
@Validated
@Tag(name = "events", description = "Security event ingestion")
public class EventController {
  private final IngestService ingest;
  private final RateLimiter limiter;
  private final IngestProperties props;

  public EventController(IngestService ingest, RateLimiter limiter, IngestProperties props) {
    this.ingest = ingest;
    this.limiter = limiter;
    this.props = props;
  }

  @PostMapping
  @Operation(
      summary = "Ingest a batch of events",
      description = "Up to ingest.max-batch events per call; duplicates by id are dropped")
  public ResponseEntity<?> ingest(
      @RequestBody @NotEmpty List<@Valid Event> events, HttpServletRequest request) {
    if (events.size() > props.maxBatch()) {
      return ResponseEntity.badRequest()
          .body(Map.of("error", "batch larger than " + props.maxBatch()));
    }
    String key = (String) request.getAttribute("apiKey");
    String limiterKey = key != null ? key : request.getRemoteAddr();
    if (!limiter.tryConsume(limiterKey, events.size())) {
      return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
          .body(Map.of("error", "rate limit exceeded"));
    }
    IngestService.Result result = ingest.accept(events);
    return ResponseEntity.accepted()
        .body(Map.of("accepted", result.accepted(), "duplicates", result.duplicates()));
  }

  @ExceptionHandler(IngestService.ProducerBackpressureException.class)
  public ResponseEntity<Map<String, String>> backpressure(
      IngestService.ProducerBackpressureException ex) {
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .header("Retry-After", "2")
        .body(Map.of("error", "pipeline is saturated, retry later"));
  }

  @ExceptionHandler({
    MethodArgumentNotValidException.class,
    jakarta.validation.ConstraintViolationException.class
  })
  public ResponseEntity<Map<String, String>> invalid(Exception ex) {
    return ResponseEntity.badRequest()
        .body(Map.of("error", "validation failed", "detail", ex.getMessage()));
  }

  @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
  public ResponseEntity<Map<String, String>> unreadable(Exception ex) {
    return ResponseEntity.badRequest().body(Map.of("error", "malformed JSON"));
  }
}
