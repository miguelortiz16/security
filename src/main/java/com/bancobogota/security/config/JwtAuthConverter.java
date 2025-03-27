package com.bancobogota.security.config;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * Clase que extiende JwtAuthenticationConverter para personalizar la conversión de roles en JWT.
 *
 * Se encarga de extraer los roles del token JWT y asignarles un prefijo "ROLE_",
 * lo cual es útil cuando se trabaja con Spring Security para la autorización basada en roles.
 */
public class JwtAuthConverter extends JwtAuthenticationConverter {

    /**
     * Constructor que configura la conversión de autoridades (roles) desde el token JWT.
     */
    public JwtAuthConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // Agrega el prefijo "ROLE_" a cada autoridad extraída del token JWT.
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        // Indica que los roles se encuentran en la claim "roles" dentro del JWT.
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");

        // Establece el convertidor de autoridades personalizado en la clase padre.
        this.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
    }
}
