package io.czen.springsecuritydemo.controller;

import io.czen.springsecuritydemo.model.Customer;
import io.czen.springsecuritydemo.repository.CustomerRepository;
import io.czen.springsecuritydemo.util.ApplicationConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class UserController {
  private final CustomerRepository customerRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final Environment env;

  public UserController(
      CustomerRepository customerRepository,
      PasswordEncoder passwordEncoder,
      AuthenticationManager authenticationManager,
      Environment env) {
    this.customerRepository = customerRepository;
    this.passwordEncoder = passwordEncoder;
    this.authenticationManager = authenticationManager;
    this.env = env;
  }

  @PostMapping("/register")
  public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequest request) {
    String hashedPassword = passwordEncoder.encode(request.password());
    Customer customer = new Customer();
    customer.setEmail(request.email());
    customer.setPassword(hashedPassword);
    customer.setRole(request.role());
    customerRepository.save(customer);
    return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping("/user")
  @ResponseStatus(HttpStatus.OK)
  public Customer getUserDetailsAfterLogin(Authentication authentication) {
    Optional<Customer> optionalCustomer = customerRepository.findByEmail(authentication.getName());
    return optionalCustomer.orElse(null);
  }

  @PostMapping("/apiLogin")
  @ResponseStatus(HttpStatus.OK)
  public LoginResponse apiLogin(@RequestBody LoginRequest request) {
    String jwt = "";
    Authentication authentication =
        UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password());
    Authentication authenticateResponse = authenticationManager.authenticate(authentication);
    if (Objects.nonNull(authenticateResponse) && Objects.nonNull(env)) {
      String secret =
          env.getProperty(
              ApplicationConstants.JWT_SECRET_KEY, ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
      SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
      jwt =
          Jwts.builder()
              .issuer("io.czen")
              .subject("JWT_TOKEN")
              .claim("username", authenticateResponse.getName())
              .claim(
                  "authorities",
                  authenticateResponse.getAuthorities().stream()
                      .map(GrantedAuthority::getAuthority)
                      .collect(Collectors.joining(",")))
              .issuedAt(new java.util.Date())
              .expiration(new java.util.Date((new java.util.Date()).getTime() + 30000000))
              .signWith(secretKey)
              .compact();
    }

    return new LoginResponse(HttpStatus.OK.getReasonPhrase(), jwt);
  }

  public record RegisterRequest(
      @NotBlank @Email String email, @NotBlank String password, @NotBlank String role) {}

  record LoginRequest(@NotBlank String username, @NotBlank String password) {}

  record LoginResponse(@NotBlank String status, @NotBlank String jwtToken) {}
}
