package io.czen.springsecuritydemo.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

  @Override
  public void handle(
      HttpServletRequest request,
      HttpServletResponse response,
      AccessDeniedException accessDeniedException)
      throws IOException {
    LocalDateTime now = LocalDateTime.now();
    String message =
        (accessDeniedException != null && accessDeniedException.getMessage() != null)
            ? accessDeniedException.getMessage()
            : "Authorization failed";
    String path = request.getRequestURI();
    response.setHeader("denied-reason", "Authorization failed");
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    String jsonResponse =
        String.format(
            "{\"timestamp\":\"%s\", \"status\":\"%d\", \"error\":\"%s\", \"message\":\"%s\", \"path\":\"%s\"}",
            now,
            HttpServletResponse.SC_FORBIDDEN,
            HttpStatus.FORBIDDEN.getReasonPhrase(),
            message,
            path);
    response.getWriter().write(jsonResponse);
  }
}
