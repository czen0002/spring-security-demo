package io.czen.springsecuritydemo.util;

public class ApplicationConstants {
  public static final String JWT_SECRET_KEY = "jwt.secret";
  public static final String JWT_SECRET_DEFAULT_VALUE =
      "a-very-long-and-secure-random-secret-key-123456";

  private ApplicationConstants() {
    throw new AssertionError("Utility class - instantiation is not allowed");
  }
}
