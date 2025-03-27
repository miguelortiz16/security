package com.bancobogota.security.config;

import com.bancobogota.security.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Collections;

/**
 * Filtro de autenticación para validar tokens JWT en cada petición.
 *
 * Extiende OncePerRequestFilter para asegurar que el filtro se ejecute solo una vez por solicitud.
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil; // Utilidad para manejar JWT

    /**
     * Constructor que recibe una instancia de JwtUtil para la validación del token.
     *
     * @param jwtUtil Objeto que maneja la generación y validación de tokens JWT.
     */
    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    /**
     * Método que intercepta cada petición y verifica si contiene un token JWT válido.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Obtiene el encabezado "Authorization" de la petición
        String header = request.getHeader("Authorization");

        // Si el header es nulo o no empieza con "Bearer ", continúa con la cadena de filtros sin autenticar
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        // Extrae el token eliminando el prefijo "Bearer "
        String token = header.replace("Bearer ", "");

        try {
            // Valida el token y obtiene los claims (información contenida en el JWT)
            Claims claims = jwtUtil.validateToken(token);
            String username = claims.getSubject(); // Obtiene el nombre de usuario desde el token
            String role = claims.get("rol", String.class);
            // Crea un objeto UserDetails con el nombre de usuario (sin roles asignados)
            UserDetails userDetails = new User(username, "", Collections.emptyList());

            // Crea una autenticación basada en el usuario extraído del token
            // Creamos la autenticación con el rol
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username, null, Collections.singletonList(new SimpleGrantedAuthority(role))
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Establece la autenticación en el contexto de seguridad de Spring
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (MalformedJwtException e) {
            // En caso de que el token sea inválido, se devuelve un error 401 (Unauthorized)
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
            return;
        }

        // Continúa con la cadena de filtros
        chain.doFilter(request, response);
    }
}
