package io.czen.springsecuritydemo.config.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthoritiesLoggingAfterFilter implements Filter {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuthoritiesLoggingAfterFilter.class);

  @Override
  public void doFilter(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (Objects.nonNull(authentication)) {
      LOGGER.info(
          "User {} is successfully authenticated and has the authorities {}",
          authentication.getName(),
          authentication.getAuthorities());
    }
    filterChain.doFilter(servletRequest, servletResponse);
  }
}
