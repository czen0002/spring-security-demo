package io.czen.springsecuritydemo.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEventListener {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationEventListener.class);

  @EventListener
  public void onAuthenticationSuccess(AuthenticationSuccessEvent successEvent) {
    LOGGER.atInfo().log("Login successful for user {}", successEvent.getAuthentication().getName());
  }

  @EventListener
  public void onAuthenticationFailure(AbstractAuthenticationFailureEvent failureEvent) {
    LOGGER
        .atError()
        .log(
            "Login failure for user {} due to [{}]",
            failureEvent.getAuthentication().getName(),
            failureEvent.getException().getMessage());
  }
}
