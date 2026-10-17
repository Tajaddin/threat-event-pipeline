package io.github.tajaddin.threat.detect.api;

import io.github.tajaddin.threat.detect.DetectProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
  private final DetectProperties props;

  public WebConfig(DetectProperties props) {
    this.props = props;
  }

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    if (!props.corsOrigins().isEmpty()) {
      registry
          .addMapping("/api/**")
          .allowedOrigins(props.corsOrigins().toArray(String[]::new))
          .allowedMethods("GET", "POST");
    }
  }
}
