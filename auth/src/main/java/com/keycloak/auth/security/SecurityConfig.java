
package com.keycloak.auth.security;

import com.keycloak.auth.config.KeycloakProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtConverter jwtConverter;
    private final KeycloakProperties keycloakProperties;

    /**
     * Configures the WebSecurity to ignore certain request paths, effectively bypassing
     * security checks for static and public resources.
     *
     * This method creates a WebSecurityCustomizer that instructs Spring Security to completely
     * ignore (not apply any security checks) requests to specified URL patterns. This is typically
     * used for publicly accessible resources like static assets.
     *
     * @return A WebSecurityCustomizer that ignores specified URL patterns
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers("/public/**", "/static/**", "/css/**", "/js/**");
    }

    /**
     * Configures the main security filter chain for the application.
     * This method sets up various security configurations including CSRF protection,
     * request authorization, OAuth2 resource server settings, and session management.
     *
     * @param http The HttpSecurity object to be configured
     * @return A SecurityFilterChain object representing the configured security filter chain
     * @throws Exception If an error occurs during the configuration process
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for APIs
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/auth/**", "/error").permitAll()
                        // Everything else must be authenticated
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter))
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }

//    /**
//     * JwtDecoder bean that fetches public keys from Keycloak’s JWKS endpoint.
//     */
//    @Bean
//    public JwtDecoder jwtDecoder() {
//        String jwkSetUri = keycloakProperties.getTokenUrl();
//        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
//    }
}
