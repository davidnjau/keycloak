package com.keycloak.auth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.keycloak.auth.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jetbrains.annotations.NotNull;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakAuthServiceImpl implements KeycloakAuthService{

    /**
     * TODO: 1. Add Redis cache for user info on the get userDetails method to improve efficiency
     * 2. Implement password hashing and salting for user passwords
     * 3. Implement email verification and password reset functionality
     * 4. Implement role-based access control (RBAC)
     * 5. Implement user profile management and update functionality
     * 6. Implement refresh token functionality
     * 7. Implement user account management and update functionality
     * 8. Implement user account lockout and password expiration functionality
     * 9. Implement user account deletion functionality
     * 10. Implement user account recovery and password reset functionality
     * 11. Update Login and Logout functionality; Wrong credentials should be handled appropriately
     *
     */

    private final RestTemplate restTemplate = new RestTemplate();
    private final KeycloakProperties keycloakProperties;
    private final Keycloak keycloak; // Injected as a @Bean

    public ApiResponse registerUser(RegisterRequest request) {

        try {
            UserRepresentation user = new UserRepresentation();
            user.setEnabled(true);
            user.setUsername(request.getUsername());
            user.setFirstName(request.getFirstName());
            user.setLastName(request.getLastName());
            user.setEmail(request.getEmail());

            RealmResource realmResource = keycloak.realm(keycloakProperties.getRealm());
            UsersResource usersResource = realmResource.users();

            Response response = usersResource.create(user);
            int statusCode = response.getStatus();

            try (response) {
                if (statusCode == Response.Status.CREATED.getStatusCode()) {
                    String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                    log.info("✅ User [{}] created successfully with ID [{}]", request.getUsername(), userId);

                    // 🔑 Set password
                    CredentialRepresentation passwordCred = new CredentialRepresentation();
                    passwordCred.setTemporary(false); // false = permanent password
                    passwordCred.setType(CredentialRepresentation.PASSWORD);
                    passwordCred.setValue(request.getPassword()); // assume your request DTO carries password

                    usersResource.get(userId).resetPassword(passwordCred);

                    // 🔑 Assign default realm role (ROLE_USER)
                    RoleRepresentation roleUser = realmResource.roles()
                            .get("ROLE_USER") // make sure ROLE_USER exists in realm
                            .toRepresentation();

                    usersResource.get(userId).roles()
                            .realmLevel()
                            .add(Collections.singletonList(roleUser));

                    /**
                     * TODO: After a user registration, you can add additional custom logic here
                     * 1. Send email verification email
                     * 2. Save additional user attributes / data in my own database
                     * 3. Handle user account status (e.g., activate/deactivate)
                     * 4. Handle user account expiration
                     * 5. Add custom logic for other user roles e.g. created by the admin interface
                     */


                    return new ApiResponse(HttpStatus.CREATED.value(), "User has been created successfully");
                } else if (statusCode == Response.Status.CONFLICT.getStatusCode()) {
                    log.warn("⚠️ User [{}] already exists", request.getUsername());
                    return new ApiResponse(HttpStatus.CONFLICT.value(), "User already exists");
                } else if (statusCode == Response.Status.UNAUTHORIZED.getStatusCode()) {
                    log.error("❌ Unauthorized when creating user [{}]. Check client roles & token.", request.getUsername());
                    return new ApiResponse(HttpStatus.UNAUTHORIZED.value(), "Unauthorized: check service account permissions");
                } else {
                    log.error("❌ Failed to create user [{}]. Status: {}", request.getUsername(), statusCode);
                    return new ApiResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            "Failed to create user: " + statusCode);
                }
            }
        } catch (Exception ex) {
            log.error("❌ Exception while creating user [{}]: {}", request.getUsername(), ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "The server could not process the data at this time.");
        }


    }

    public ApiResponse login(LoginRequest request) {

        try {
            // Build a Keycloak instance specifically for user login (password grant)
            Keycloak userKeycloak = KeycloakBuilder.builder()
                    .serverUrl(keycloakProperties.getServerUrl())
                    .realm(keycloakProperties.getRealm())
                    .clientId(keycloakProperties.getClientId())
                    .clientSecret(keycloakProperties.getClientSecret()) // confidential client
                    .username(request.getUsername())
                    .password(request.getPassword())
                    .grantType(OAuth2Constants.PASSWORD)
                    .resteasyClient(new ResteasyClientBuilder()
                            .connectionPoolSize(10)
                            .build())
                    .build();

            // Request access token
            AccessTokenResponse tokenResponse = userKeycloak.tokenManager().getAccessToken();

            LoginResponse loginResponse = new LoginResponse(
                    tokenResponse.getToken(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getExpiresIn()
            );
            return new ApiResponse(HttpStatus.OK.value(), loginResponse);


        } catch (Exception e) {
            throw new RuntimeException("Login failed: " + e.getMessage(), e);
        }

    }

    public ApiResponse getUserInfo(Authentication authentication) {
        try {

            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();

            String userId = jwt.getSubject();
            String email = jwt.getClaim("email");
            String fullName = jwt.getClaim("name");
            Object realmAccess = jwt.getClaim("realm_access");

            List<String> rolesWithPrefix = getUserRoles(realmAccess);

            // Build response
            UserInfoResponse userInfoResponse = new UserInfoResponse(userId, email, fullName, rolesWithPrefix);
            return new ApiResponse(HttpStatus.OK.value(), userInfoResponse);

        } catch (Exception ex) {
            log.error("❌ User information could not be found [{}]: {}", authentication, ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.UNAUTHORIZED.value(),
                    "Unauthorized access.");
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getUserRoles(Object rolesSource) {
        List<String> rolesWithPrefix = new ArrayList<>();

        if (rolesSource == null) {
            return rolesWithPrefix;
        }

        // Case 1: roles from JWT realm_access claim (Map<String, Object>)
        if (rolesSource instanceof Map) {
            Map<String, Object> realmAccessMap = (Map<String, Object>) rolesSource;

            Object rolesObj = realmAccessMap.get("roles");
            if (rolesObj instanceof List) {
                List<String> roles = (List<String>) rolesObj;

                rolesWithPrefix = roles.stream()
                        .filter(role -> role.startsWith("ROLE_"))
                        .collect(Collectors.toList());
            }
        }

        // Case 2: roles directly as a List<String>
        else if (rolesSource instanceof List) {
            List<?> rawRoles = (List<?>) rolesSource;

            rolesWithPrefix = rawRoles.stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (String) role)
                    .filter(role -> role.startsWith("ROLE_"))
                    .collect(Collectors.toList());
        }

        return rolesWithPrefix;
    }


    @Override
    public ApiResponse getUserDetails(String userId) {

        try {

            UserResource userResource = keycloak
                    .realm(keycloakProperties.getRealm())
                    .users()
                    .get(userId);

            UserRepresentation user = userResource.toRepresentation();
            String email = user.getEmail();
            String fullName = user.getFirstName() + " " + user.getLastName();
            Boolean isVerified = user.isEmailVerified();
            Boolean isEnabled = user.isEnabled();

            List<String> roles = new ArrayList<>();

            // ✅ Realm-level roles
            List<RoleRepresentation> realmRoles = userResource.roles().realmLevel().listEffective();
            for (RoleRepresentation role : realmRoles) {
                roles.add(role.getName());
            }

            // ✅ Client-level roles (for your client)
            String clientId = keycloak.realm(keycloakProperties.getRealm())
                    .clients()
                    .findByClientId(keycloakProperties.getClientId())
                    .get(0)
                    .getId();

            List<RoleRepresentation> clientRoles = userResource.roles()
                    .clientLevel(clientId)
                    .listEffective();
            for (RoleRepresentation role : clientRoles) {
                roles.add(role.getName());
            }

            List<String> rolesWithPrefix = getUserRoles(roles);
            UserInfoResponse userInfoResponse = new UserInfoResponse(userId, email, fullName, rolesWithPrefix);
            return new ApiResponse(HttpStatus.OK.value(), userInfoResponse);

        }catch (Exception ex) {
            log.error("❌ The user id could not be found [{}]: {}", userId, ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.NOT_FOUND.value(),
                    "The user id could not be found.");
        }


    }

    @Override
    public ApiResponse refreshToken(RefreshTokenDtO dto) {

        String refreshToken = dto.getRefreshToken();
        try {
            if (refreshToken.isEmpty()) {
                return new ApiResponse(HttpStatus.UNAUTHORIZED.value(),
                        "Refresh token is required" );
            }

            // Prepare HTTP headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // Prepare request body
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("client_id", keycloakProperties.getClientId());
            body.add("client_secret", keycloakProperties.getClientSecret());
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            // Make the request
            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    keycloakProperties.getTokenUrl(),
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<>() {}
            );

            Map<String, Object> tokenResponse = response.getBody();
            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return new ApiResponse(HttpStatus.UNAUTHORIZED.value(),
                        "Invalid or expired refresh token" );
            }

            String accessToken = (String) tokenResponse.get("access_token");
            String newRefreshToken = (String) tokenResponse.get("refresh_token");
            DecodedJWT decodedJWT = JWT.decode(accessToken);
            LoginResponse loginResponse = getLoginResponse(decodedJWT, accessToken, newRefreshToken);
            return new ApiResponse(HttpStatus.OK.value(), loginResponse);

        } catch (Exception ex) {
            // Log the exception
            log.error("Failed to refresh token: {}", ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.UNAUTHORIZED.value(),
                    "Failed to refresh token: " + ex.getMessage());
        }


    }

    @NotNull
    private static LoginResponse getLoginResponse(DecodedJWT decodedJWT, String accessToken, String newRefreshToken) {
        Date expirationDate = decodedJWT.getExpiresAt();

        // Current time
        Date now = new Date();

        // Calculate difference in milliseconds
        long diffMillis = expirationDate.getTime() - now.getTime();

        // Convert to seconds, minutes, hours if needed
        long diffSeconds = diffMillis / 1000;
        long diffMinutes = diffSeconds / 60;
        long diffHours = diffMinutes / 60;

        LoginResponse loginResponse = new LoginResponse(
                accessToken,
                newRefreshToken,
                diffSeconds
        );
        return loginResponse;
    }

}
