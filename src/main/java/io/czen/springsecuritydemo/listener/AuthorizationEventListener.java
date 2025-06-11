package io.czen.springsecuritydemo.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationEventListener {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationEventListener.class);

  @EventListener
  public void onAuthorizationFailure(AuthorizationDeniedEvent deniedEvent) {
    LOGGER
        .atError()
        .log(
            "Authorization failed for the user: {} due to: {}",
            deniedEvent.getAuthentication().get().getName(),
            deniedEvent.getAuthorizationResult().toString());
  }
}
