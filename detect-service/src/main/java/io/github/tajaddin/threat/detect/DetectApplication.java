package io.github.tajaddin.threat.detect;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class DetectApplication {
  public static void main(String[] args) {
    SpringApplication.run(DetectApplication.class, args);
  }
}
