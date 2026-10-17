package io.github.tajaddin.threat.index;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class IndexApplication {
  public static void main(String[] args) {
    SpringApplication.run(IndexApplication.class, args);
  }
}
