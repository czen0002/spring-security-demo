package io.czen.springsecuritydemo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class GreetingsController {

  @GetMapping("/greetings")
  public ResponseEntity<String> sayHello() {
    return ResponseEntity.ok("Hello from API");
  }

  @GetMapping("/farewell")
  public ResponseEntity<String> sayGoodbye() {
    return ResponseEntity.ok("Goodbye from API");
  }
}
