package com.bancobogota.security.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.util.Date;

/**
 * Clase para generar tokens JWT de prueba.
 */
public class JwtGenerator {

    /**
     * Genera un token JWT con un usuario de prueba y un rol.
     *
     * @return Token JWT como cadena de texto.
     */
    public static String generateToken() {
        return JWT.create()
                .withClaim("scope", "read") // Permiso necesario (SCOPE_read)
                .withSubject("testUser") // Define el usuario asociado al token
                .withIssuedAt(new Date()) // Establece la fecha de emisión
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600 * 1000)) // Expira en 1 hora
                .sign(Algorithm.HMAC256("mi_secreto")); // Firma el token con una clave secreta
    }

    /**
     * Método principal para ejecutar la generación del token y mostrarlo en consola.
     */
    public static void main(String[] args) {
        System.out.println("Token JWT: " + generateToken());
    }
}
