package io.czen.springsecuritydemo.config;

import io.czen.springsecuritydemo.model.Customer;
import io.czen.springsecuritydemo.repository.CustomerRepository;
import java.util.List;
import java.util.Locale;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class MyUserDetailService implements UserDetailsService {
  private final CustomerRepository customerRepository;

  public MyUserDetailService(CustomerRepository customerRepository) {
    this.customerRepository = customerRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Customer customer =
        this.customerRepository
            .findByEmail(username.toLowerCase(Locale.ROOT))
            .orElseThrow(
                () ->
                    new UsernameNotFoundException(
                        "User details not found for the user: " + username));
    List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(customer.getRole()));

    return new User(customer.getEmail(), customer.getPassword(), authorities);
  }
}
