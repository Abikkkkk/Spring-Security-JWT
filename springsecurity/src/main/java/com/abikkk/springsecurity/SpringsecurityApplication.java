package com.abikkk.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.security.auth.login.AccountException;

@SpringBootApplication
public class SpringsecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecurityApplication.class, args);
	}

}

/**
 *
 * Application Context:
Users should be able to
 - Register to the application with a Role.
 - Login to the application (using Registered Credentials).
 - JWT Token is generated.
 - The generated token is then used to authorize access to Role specific data.
 **/