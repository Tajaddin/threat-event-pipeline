package io.github.tajaddin.threat.detect.api;

import io.github.tajaddin.threat.detect.DetectProperties;
import jakarta.servlet.DispatcherType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * Access rules for the alert API: alerts, rules, stats and the rule reload need an X-API-Key from
 * {@code detect.api-keys}; probes, metrics and the API docs are open; anything else is refused.
 * Matching uses the normalised path Spring MVC routes on. The console's proxy adds the key on the
 * server side, so it never reaches a browser. An empty key list leaves {@code /api/**} open, which
 * is for local development only; with {@code detect.require-api-keys} the service does not start
 * without a key.
 */
@Configuration
public class SecurityConfig {
  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http, DetectProperties props)
      throws Exception {
    boolean open = props.apiKeys().isEmpty();
    if (open) {
      log.warn("detect.api-keys is empty: /api/** accepts requests without a key");
    }
    http.csrf(AbstractHttpConfigurer::disable)
        .cors(Customizer.withDefaults())
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
