package com.daveace.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class AuthorizationserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationserverApplication.class, args);
	}

	@GetMapping("/redirect/authorized")
	public String redirectPage() {
		return "redirect";
	}

}
