package io.github.tajaddin.threat.common;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.regex.Pattern;

/**
 * An IPv4 address in dotted-quad form or an IPv6 address in RFC 4291 text form (without a zone id).
 * Null is valid. Enrichment casts these values to Postgres {@code inet}, so anything else would
 * fail there instead of at the API.
 */
@Documented
@Constraint(validatedBy = IpAddress.Validator.class)
@Target({FIELD, METHOD, PARAMETER, TYPE_USE})
@Retention(RUNTIME)
public @interface IpAddress {
  String message() default "must be an IPv4 or IPv6 address";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  /** Parses the text only; it never resolves a name. */
  final class Validator implements ConstraintValidator<IpAddress, String> {
    private static final String OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
    private static final Pattern IPV4 = Pattern.compile(OCTET + "(\\." + OCTET + "){3}");
    private static final Pattern HEX_GROUP = Pattern.compile("[0-9A-Fa-f]{1,4}");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
      return value == null || isLiteral(value);
    }

    public static boolean isLiteral(String text) {
      return IPV4.matcher(text).matches() || isIpv6(text);
    }

    private static boolean isIpv6(String text) {
      int lastColon = text.lastIndexOf(':');
      if (lastColon < 0) {
        return false;
      }
      String groups = text;
      if (text.indexOf('.', lastColon) >= 0) {
        // an embedded IPv4 address stands for the last two groups
        if (!IPV4.matcher(text.substring(lastColon + 1)).matches()) {
          return false;
        }
        groups = text.substring(0, lastColon + 1) + "0:0";
      }
      int gap = groups.indexOf("::");
      if (gap < 0) {
        return count(groups) == 8;
      }
      if (groups.indexOf("::", gap + 1) >= 0) {
        return false;
      }
      String head = groups.substring(0, gap);
      String tail = groups.substring(gap + 2);
      int h = head.isEmpty() ? 0 : count(head);
      int t = tail.isEmpty() ? 0 : count(tail);
      return h >= 0 && t >= 0 && h + t <= 7;
    }

    /** Number of colon-separated groups of one to four hex digits, or -1 if one is malformed. */
    private static int count(String part) {
      String[] groups = part.split(":", -1);
      for (String g : groups) {
        if (!HEX_GROUP.matcher(g).matches()) {
          return -1;
        }
      }
      return groups.length;
    }
  }
}
