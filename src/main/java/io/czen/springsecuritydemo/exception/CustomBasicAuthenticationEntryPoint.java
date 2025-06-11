package io.czen.springsecuritydemo.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException {
    LocalDateTime now = LocalDateTime.now();
    String message =
        (authException != null && authException.getMessage() != null)
            ? authException.getMessage()
            : "Unauthorized";
    String path = request.getRequestURI();
    response.setHeader("error-reason", "Authentication failed");
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    String jsonResponse =
        String.format(
            "{\"timestamp\":\"%s\", \"status\":\"%d\", \"error\":\"%s\", \"message\":\"%s\", \"path\":\"%s\"}",
            now,
            HttpServletResponse.SC_UNAUTHORIZED,
            HttpStatus.UNAUTHORIZED.getReasonPhrase(),
            message,
            path);
    response.getWriter().write(jsonResponse);
  }
}
