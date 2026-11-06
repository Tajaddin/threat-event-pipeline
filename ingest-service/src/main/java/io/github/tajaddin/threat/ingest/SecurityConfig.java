package io.github.tajaddin.threat.ingest;

import jakarta.servlet.DispatcherType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * Access rules. Spring Security matches requests on the same normalised path Spring MVC routes on,
 * and its firewall rejects path parameters and encoded separators, so {@code /api;x/events} or
 * {@code /%61pi/events} cannot reach a controller without the key. Probes, metrics and the API docs
 * are open; anything not listed is refused. An empty key list leaves {@code /api/**} open, which is
 * for local development only; with {@code ingest.require-api-keys} the service does not start
 * without a key.
 */
@Configuration
public class SecurityConfig {
  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http, IngestProperties props)
      throws Exception {
    boolean open = props.apiKeys().isEmpty();
    if (open) {
      log.warn("ingest.api-keys is empty: /api/** accepts requests without a key");
    }
    http.csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .requestCache(AbstractHttpConfigurer::disable)
        .addFilterBefore(new ApiKeyFilter(props.apiKeys()), AnonymousAuthenticationFilter.class)
        .exceptionHandling(e -> e.authenticationEntryPoint(ApiKeyFilter::unauthorized))
        .authorizeHttpRequests(
            auth -> {
              auth.dispatcherTypeMatchers(DispatcherType.ERROR)
                  .permitAll()
                  .requestMatchers(EndpointRequest.to("health", "info", "prometheus", "metrics"))
                  .permitAll()
                  .requestMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                  .permitAll();
              var api = auth.requestMatchers("/api/**");
              if (open) {
                api.permitAll();
              } else {
                api.authenticated();
              }
              auth.anyRequest().denyAll();
            });
    return http.build();
  }
}
