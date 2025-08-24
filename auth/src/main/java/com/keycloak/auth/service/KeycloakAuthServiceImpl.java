package com.keycloak.auth.service;

import com.keycloak.auth.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
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

    public LoginResponse login(LoginRequest request) {

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

            return new LoginResponse(
                    tokenResponse.getToken(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getExpiresIn()
            );

        } catch (Exception e) {
            throw new RuntimeException("Login failed: " + e.getMessage(), e);
        }

    }

    public UserInfoResponse getUserInfo(Authentication authentication) {
        try {

            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();

            String userId = jwt.getSubject();
            String email = jwt.getClaim("email");
            String fullName = jwt.getClaim("name");
            Object realmAccess = jwt.getClaim("realm_access");

            List<String> rolesWithPrefix = new ArrayList<>();

            if (realmAccess instanceof Map) {
                Map<String, Object> realmAccessMap = (Map<String, Object>) realmAccess;

                Object rolesObj = realmAccessMap.get("roles");
                if (rolesObj instanceof List) {
                    List<String> roles = (List<String>) rolesObj;

                    rolesWithPrefix = roles.stream()
                            .filter(role -> role.startsWith("ROLE_"))
                            .collect(Collectors.toList());
                }
            }

            // Build response
            return new UserInfoResponse(userId, email, fullName, rolesWithPrefix);

        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }

    @Override
    public UserInfoResponse getUserDetails(String userId) {

        UserResource userResource = keycloak
                .realm(keycloakProperties.getRealm())
                .users()
                .get(userId);

        UserRepresentation user = userResource.toRepresentation();
        String email = user.getEmail();
        String fullName = user.getFirstName() + " " + user.getLastName();
        Boolean isVerified = user.isEmailVerified();
        Boolean isEnabled = user.isEnabled();
        List<String> roles = user.getRealmRoles();

        System.out.println("********");
        System.out.println("email "+email);
        System.out.println("fullName "+fullName);
        System.out.println("isVerified "+isVerified);
        System.out.println("isEnabled "+isEnabled);
        System.out.println("roles "+roles);
        System.out.println("********");

        return new UserInfoResponse(userId, email, fullName, roles);


//        Map<String, Object> userInfo = new HashMap<>();
//        userInfo.put("id", user.getId());
//        userInfo.put("username", user.getUsername());
//        userInfo.put("email", user.getEmail());
//        userInfo.put("firstName", user.getFirstName());
//        userInfo.put("lastName", user.getLastName());
//        userInfo.put("enabled", user.isEnabled());

//        return null;
    }

}
