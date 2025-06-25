package io.czen.springsecuritydemo.config;

import static org.springframework.security.config.Customizer.withDefaults;

import io.czen.springsecuritydemo.config.filter.AuthoritiesLoggingAfterFilter;
import io.czen.springsecuritydemo.config.filter.JWTTokenGeneratorFilter;
import io.czen.springsecuritydemo.config.filter.JWTTokenValidatorFilter;
import io.czen.springsecuritydemo.config.filter.RequestValidationBeforeFilter;
import io.czen.springsecuritydemo.exception.CustomAccessDeniedHandler;
import io.czen.springsecuritydemo.exception.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(
            smc ->
                smc.invalidSessionUrl("/invalidSession")
                    .maximumSessions(3)
                    .maxSessionsPreventsLogin(true)
                    .expiredUrl("/invalidSession"))
        .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // HTTP only
        //        .requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) // HTTPS only
        .csrf(AbstractHttpConfigurer::disable)
        .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
        .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
        .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
        .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
        .authorizeHttpRequests(
            requests ->
                requests
                    //                    .requestMatchers("/api/v1/greetings")
                    //                    .authenticated() // authentication
                    //                    .requestMatchers("/api/v1/greetings")
                    //                    .hasAnyAuthority("ROLE_ADMIN") // authorization via
                    // authority
                    .requestMatchers("/api/v1/greetings")
                    .hasAnyRole(
                        "ADMIN") // authorization via role "ROLE_"prefix can be customized by
                    // @GrantedAuthorityDefaults(rolePrefix = "ROLE_")
                    .requestMatchers(
                        "/api/v1/farewell",
                        "/api/v1/register",
                        "/api/v1/apiLogin",
                        "/invalidSession",
                        "/error")
                    .permitAll()
                    .requestMatchers("/api/v1/user")
                    .authenticated());
    http.formLogin(withDefaults());
    //    http.formLogin(AbstractHttpConfigurer::disable);
    //    http.httpBasic(withDefaults());
    http.httpBasic(htb -> htb.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
    http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
    return http.build();
  }

  //  @Bean
  //  public UserDetailsService userDetailsService() {
  //    UserDetails user =
  //
  // User.withUsername("user").password("{noop}Final135Fantasy!").authorities("read").build();
  //    UserDetails admin =
  //        User.withUsername("admin")
  //            .password("{bcrypt}$2a$12$F957ZR9njP0.PPlFqs/gj.ShqWZFghUG9mgivPIEr9TN12MOvX0de")
  //            .authorities("admin")
  //            .build();
  //    return new InMemoryUserDetailsManager(user, admin);
  //  }

  //  @Bean
  //  public UserDetailsService userDetailsService(DataSource dataSource) {
  //    return new JdbcUserDetailsManager(dataSource);
  //  }

  // This is the default one
  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  // check if the password has been compromised https://haveibeenpwned.com/API/v3#PwnedPasswords
  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker() {
    return new HaveIBeenPwnedRestApiPasswordChecker();
  }

  @Bean
  public AuthenticationManager authenticationManager(
      UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    MyAuthenticationProvider authenticationProvider =
        new MyAuthenticationProvider(userDetailsService, passwordEncoder);
    ProviderManager providerManager = new ProviderManager(authenticationProvider);
    providerManager.setEraseCredentialsAfterAuthentication(false);
    return providerManager;
  }
}
