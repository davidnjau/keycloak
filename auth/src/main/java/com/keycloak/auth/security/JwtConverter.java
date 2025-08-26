
package com.keycloak.auth.security;

import com.keycloak.auth.config.KeycloakProperties;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class JwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

    private final KeycloakProperties keycloakProperties;


    /**
     * Converts a JWT token into an AbstractAuthenticationToken.
     * This method combines the authorities from the JWT with resource roles
     * and creates a new JwtAuthenticationToken.
     *
     * @param jwt The JWT token to be converted. Must not be null.
     * @return An AbstractAuthenticationToken containing the JWT, combined authorities,
     *         and the principal claim name.
     */
    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {

        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipleClaimName(jwt)
        );
    }

    /**
     * Retrieves the principal claim name from the JWT.
     * 
     * This method determines the claim name to be used as the principal. It defaults to
     * the subject claim (JwtClaimNames.SUB) but can be overridden by the principle attribute
     * specified in the Keycloak properties.
     *
     * @param jwt The JWT token from which to extract the claim. Must not be null.
     * @return The value of the determined principal claim from the JWT.
     */
    private String getPrincipleClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (keycloakProperties.getPrincipleAttribute() != null) {
            claimName = keycloakProperties.getPrincipleAttribute();
        }
        return jwt.getClaim(claimName);
    }

    /**
     * Extracts resource roles from the given JWT and converts them into a collection of GrantedAuthority objects.
     * 
     * This method processes the "resource_access" claim of the JWT, specifically looking for roles
     * associated with the client ID specified in the Keycloak properties. Each role is prefixed with "ROLE_"
     * and converted into a SimpleGrantedAuthority.
     *
     * @param jwt The JWT token from which to extract resource roles. Must not be null.
     * @return A collection of GrantedAuthority objects representing the resource roles.
     *         Returns an empty set if no resource roles are found or if the necessary claims are missing.
     */
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        if (jwt.getClaim("resource_access") == null) {
            return Set.of();
        }
        resourceAccess = jwt.getClaim("resource_access");

        if (resourceAccess.get(keycloakProperties.getClientId()) == null) {
            return Set.of();
        }
        resource = (Map<String, Object>) resourceAccess.get(keycloakProperties.getClientId());

        resourceRoles = (Collection<String>) resource.get("roles");

        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}
