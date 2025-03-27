package com.bancobogota.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Clase de utilidad para la generación y validación de tokens JWT.
 */
@Component
public class JwtUtil {
    // 🔥 Clave secreta para firmar los tokens (debe ser segura y almacenada correctamente)
    private final String SECRET_KEY = "a5rnHwyJ3KKOUoNaCau7oQipFqEx4U9wfkFcQvdRgXY=";

    /**
     * Genera un token JWT para un usuario específico.
     *
     * @param username Nombre de usuario para el token.
     * @return Token JWT generado.
     */
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>(); // Puede contener información adicional
        claims.put("rol","ADMIN");
        return Jwts.builder()
                .setClaims(claims) // Agrega claims (vacío en este caso)
                .setSubject(username) // Define el usuario como sujeto del token
                .setIssuedAt(new Date(System.currentTimeMillis())) // Fecha de emisión
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // Expira en 1 hora
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // Firma con algoritmo HMAC SHA-256
                .compact(); // Compacta y genera el token
    }

    /**
     * Valida y extrae los claims de un token JWT.
     *
     * @param token Token JWT recibido.
     * @return Claims (información del token).
     * @throws io.jsonwebtoken.JwtException si el token es inválido o expirado.
     */
    public Claims validateToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY) // Clave secreta para validar el token
                .parseClaimsJws(token) // Parsea el token
                .getBody(); // Extrae los claims
    }
}
