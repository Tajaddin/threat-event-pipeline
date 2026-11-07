package io.github.tajaddin.threat.detect.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates a request whose X-API-Key matches a configured key. It only establishes who the
 * caller is; {@link SecurityConfig} decides which paths need that. The principal is the key's
 * position in the list, so the key itself never reaches the logs.
 */
final class ApiKeyFilter extends OncePerRequestFilter {
  static final String HEADER = "X-API-Key";

  private final List<String> keys;

  ApiKeyFilter(List<String> keys) {
    this.keys = List.copyOf(keys);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String presented = request.getHeader(HEADER);
    int match = presented == null ? -1 : indexOf(presented);
    if (match >= 0) {
      SecurityContext context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(
          UsernamePasswordAuthenticationToken.authenticated(
              "api-key-" + match, null, AuthorityUtils.NO_AUTHORITIES));
      SecurityContextHolder.setContext(context);
    }
    chain.doFilter(request, response);
  }

  /** Compares against every key, so the time taken does not reveal which one came close. */
  private int indexOf(String presented) {
    int match = -1;
    for (int i = 0; i < keys.size(); i++) {
      if (constantTimeEquals(keys.get(i), presented) && match < 0) {
        match = i;
      }
    }
    return match;
  }

  static boolean constantTimeEquals(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  static void unauthorized(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
      throws IOException {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"invalid or missing X-API-Key\"}");
  }
}
