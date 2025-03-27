package com.bancobogota.security.config;

import com.bancobogota.security.utils.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuración de seguridad para la aplicación con Spring Security y JWT.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtUtil jwtUtil;

    /**
     * Constructor que inyecta la utilidad de JWT.
     *
     * @param jwtUtil Utilidad para manejo de tokens JWT.
     */
    public SecurityConfig(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    /**
     * Configuración de la cadena de filtros de seguridad.
     *
     * @param http Objeto HttpSecurity para configurar la seguridad de la aplicación.
     * @return SecurityFilterChain configurado.
     * @throws Exception Si hay un error en la configuración.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable() // Desactiva la protección CSRF (Cross-Site Request Forgery)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login").permitAll() // Permite acceso sin autenticación a /auth/login
                        .requestMatchers("/resource/user").authenticated() // Requiere autenticación con JWT
                        .requestMatchers("/resource/data").authenticated() // Requiere autenticación con JWT
                        .anyRequest().authenticated() // Todas las demás peticiones requieren autenticación
                )
                // Agrega el filtro JWT antes del filtro de autenticación de usuario y contraseña
                .addFilterBefore(new JwtAuthFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
