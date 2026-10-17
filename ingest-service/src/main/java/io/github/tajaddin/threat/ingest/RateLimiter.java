package io.github.tajaddin.threat.ingest;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import java.time.Duration;
import org.springframework.stereotype.Component;

/**
 * Token bucket per API key (or client address), sized in events per minute so a batch of 500 costs
 * 500.
 */
@Component
public class RateLimiter {
  private final IngestProperties props;
  private final Cache<String, Bucket> buckets =
      Caffeine.newBuilder().expireAfterAccess(Duration.ofMinutes(10)).maximumSize(10_000).build();

  public RateLimiter(IngestProperties props) {
    this.props = props;
  }

  public boolean tryConsume(String key, long events) {
    Bucket bucket =
        buckets.get(
            key,
            k ->
                Bucket.builder()
                    .addLimit(
                        Bandwidth.builder()
                            .capacity(props.rateLimitPerMinute())
                            .refillGreedy(props.rateLimitPerMinute(), Duration.ofMinutes(1))
                            .build())
                    .build());
    return bucket.tryConsume(events);
  }
}
