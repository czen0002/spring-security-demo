package io.czen.springsecuritydemo.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
  //  @ExceptionHandler(BadCredentialsException.class)
  //  public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException ex) {
  //    Map<String, Object> errorResponse = new HashMap<>();
  //    errorResponse.put("timestamp", LocalDateTime.now());
  //    errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());
  //    errorResponse.put("error", "Unauthorized");
  //    errorResponse.put("message", "Invalid username or password");
  //    errorResponse.put("path", "/api/v1/greetings"); // You can make this dynamic if needed
  //
  //    return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
  //  }

  // Alternative simpler version
  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<String> handleBadCredentialsSimple(BadCredentialsException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body("Authentication failed: Invalid credentials");
  }

  //  // If you want to handle other security exceptions as well
  //  @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
  //  public ResponseEntity<Map<String, Object>> handleAccessDenied(
  //      org.springframework.security.access.AccessDeniedException ex) {
  //    Map<String, Object> errorResponse = new HashMap<>();
  //    errorResponse.put("timestamp", LocalDateTime.now());
  //    errorResponse.put("status", HttpStatus.FORBIDDEN.value());
  //    errorResponse.put("error", "Forbidden");
  //    errorResponse.put("message", "Access denied - insufficient privileges");
  //
  //    return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
  //  }
}
