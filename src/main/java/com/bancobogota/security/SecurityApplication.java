package com.bancobogota.security;

import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;

import java.util.Base64;

import static com.bancobogota.security.config.JwtGenerator.generateToken;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
		String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
		System.out.println("Clave secreta segura (Base64): " + encodedKey);
		System.out.println("Token JWT: " + generateToken());
		SpringApplication.run(SecurityApplication.class, args);
	}

}
