package io.czen.springsecuritydemo.config.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;

public class RequestValidationBeforeFilter implements Filter {

  private static final String BASIC_AUTH = "Basic ";

  @Override
  public void doFilter(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) servletRequest;
    HttpServletResponse res = (HttpServletResponse) servletResponse;

    String header = req.getHeader(HttpHeaders.AUTHORIZATION);
    if (Objects.nonNull(header) && header.trim().startsWith(BASIC_AUTH)) {
      try {
        byte[] decoded = Base64.getDecoder().decode(header.substring(BASIC_AUTH.length()));
        String token = new String(decoded, StandardCharsets.UTF_8);
        int delim = token.indexOf(':');
        if (delim == -1) {
          throw new BadCredentialsException("Invalid Basic Authentication Token");
        }
        String email = token.substring(0, delim);
        if (email.toLowerCase().contains("test")) {
          res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
          return;
        }
      } catch (IllegalArgumentException e) {
        throw new BadCredentialsException("Invalid Basic Authentication Token");
      }
    }
    filterChain.doFilter(req, res);
  }
}
