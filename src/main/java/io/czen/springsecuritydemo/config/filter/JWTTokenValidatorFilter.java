package io.czen.springsecuritydemo.config.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import javax.crypto.SecretKey;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String jwt = request.getHeader("Authorization");
    if (Objects.nonNull(jwt)) {
      try {
        Environment env = getEnvironment();
        String secret =
            env.getProperty("jwt.secret", "a-very-long-and-secure-random-secret-key-123456");
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();
        String username = String.valueOf(claims.get("username"));
        String authorities = String.valueOf(claims.get("authorities"));
        Authentication authentication =
            new UsernamePasswordAuthenticationToken(
                username, null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } catch (SignatureException e) {
        handleJwtException(response, "JWT signature validation failed", HttpStatus.UNAUTHORIZED);
        return;
      } catch (ExpiredJwtException e) {
        handleJwtException(response, "JWT token has expired", HttpStatus.UNAUTHORIZED);
        return;
      } catch (MalformedJwtException e) {
        handleJwtException(response, "Invalid JWT token format", HttpStatus.BAD_REQUEST);
        return;
      } catch (Exception e) {
        handleJwtException(response, "JWT token validation failed", HttpStatus.UNAUTHORIZED);
        return;
      }
    }
    filterChain.doFilter(request, response);
  }

  private void handleJwtException(HttpServletResponse response, String message, HttpStatus status)
      throws IOException {
    response.setStatus(status.value());
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");

    String jsonResponse =
        String.format(
            """
            {
                "timestamp": "%s",
                "status": %d,
                "error": "%s",
                "message": "%s",
                "path": "%s"
            }
            """,
            Instant.now().toString(),
            status.value(),
            status.getReasonPhrase(),
            message,
            getCurrentRequestPath());

    response.getWriter().write(jsonResponse);
    response.getWriter().flush();
  }

  private String getCurrentRequestPath() {
    try {
      HttpServletRequest request =
          ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
      return request.getRequestURI();
    } catch (Exception e) {
      return "/unknown";
    }
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return request.getServletPath().equals("/api/v1/user");
  }
}
