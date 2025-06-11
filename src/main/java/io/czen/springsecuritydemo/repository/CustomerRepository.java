package io.czen.springsecuritydemo.repository;

import io.czen.springsecuritydemo.model.Customer;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CustomerRepository extends CrudRepository<Customer, Long> {
  Optional<Customer> findByEmail(String email);
}
