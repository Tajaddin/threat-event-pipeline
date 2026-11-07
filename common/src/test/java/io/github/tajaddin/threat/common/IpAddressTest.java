package io.github.tajaddin.threat.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class IpAddressTest {

  @ParameterizedTest
  @ValueSource(
      strings = {
        "10.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::",
        "::1",
        "1::",
        "2001:db8::1",
        "2001:DB8:0:0:8:800:200C:417A",
        "1:2:3:4:5:6:7::",
        "::ffff:192.0.2.1",
        "1:2:3:4:5:6:192.0.2.1"
      })
  void acceptsAddressLiterals(String ip) {
    assertThat(IpAddress.Validator.isLiteral(ip)).as(ip).isTrue();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "x",
        "",
        "localhost",
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "01.2.3.4",
        " 10.0.0.1",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7",
        ":::",
        "1::2::3",
        ":1:2:3:4:5:6:7",
        "2001:db8::g",
        "12345::",
        "fe80::1%eth0",
        "[::1]",
        "1.2.3.4::",
        "1:2:3:4:5:6:7::192.0.2.1",
        "::ffff:192.0.2.256"
      })
  void rejectsEverythingElse(String ip) {
    assertThat(IpAddress.Validator.isLiteral(ip)).as(ip).isFalse();
  }
}
