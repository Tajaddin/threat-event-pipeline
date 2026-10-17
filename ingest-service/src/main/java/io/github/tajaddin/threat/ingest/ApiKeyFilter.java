package io.github.tajaddin.threat.ingest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * X-API-Key check for the write endpoints. Health, metrics and docs stay open for probes and
 * reviewers.
 */
@Component
public class ApiKeyFilter extends OncePerRequestFilter {
  private final IngestProperties props;

  public ApiKeyFilter(IngestProperties props) {
    this.props = props;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String p = request.getRequestURI();
    return !p.startsWith("/api/") || props.apiKeys().isEmpty();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String key = request.getHeader("X-API-Key");
    if (key == null || props.apiKeys().stream().noneMatch(k -> constantTimeEquals(k, key))) {
      response.setStatus(401);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"invalid or missing X-API-Key\"}");
      return;
    }
    request.setAttribute("apiKey", key);
    chain.doFilter(request, response);
  }

  static boolean constantTimeEquals(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }
}
