package com.keycloak.auth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.keycloak.auth.*;
import com.keycloak.auth.config.KeycloakConfig;
import com.keycloak.auth.config.KeycloakProperties;
import com.keycloak.auth.config.UserInputValidator;
import com.keycloak.common.exception.BadRequestException;
import com.keycloak.common.exception.ConflictException;
import com.keycloak.common.exception.InternalServerException;
import com.keycloak.common.exception.UnauthorizedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.var;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jetbrains.annotations.NotNull;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakAuthServiceImpl implements KeycloakAuthService{

    /**
     * TODO:
     * 1. Add Redis cache for user info on the get userDetails method to improve efficiency
     * 2. Implement email verification
     * 3. Update Login and Logout functionality; Wrong credentials should be handled appropriately
     * 4. Save additional user attributes / data in my own database
     */

    private final KeycloakProperties keycloakProperties;
//    private final Keycloak keycloak; // Injected as a @Bean
    private final KeycloakConfig keycloak; // Injected as a @Bean
    private final RedisTemplate<String, Object> redisTemplate;
    private static final long CACHE_TTL = 10; // minutes
    private final UserInputValidator userInputValidator;


    @Override
    @Transactional
    public String registerUser(RegisterRequest request) throws BadRequestException{
        log.info("Starting user registration for username: {}", request.getUsername());

        // Validate input
        userInputValidator.validateRegistrationRequest(request);

        // Check if user already exists
        if (userExists(request.getUsername(), request.getEmail())) {
            log.warn("Registration failed - user already exists: {}", request.getUsername());
            throw new ConflictException("User already exists");
        }

        UserRepresentation user = buildUserRepresentation(request);

        RealmResource realmResource = keycloak
                .serviceAccountKeycloakClient()
                .realm(keycloakProperties.getRealm());
        UsersResource usersResource = realmResource.users();

        Response response = usersResource.create(user);
        int statusCode = response.getStatus();

        if (statusCode != Response.Status.CREATED.getStatusCode()) {
            log.error("Failed to create user: {}", response.readEntity(String.class));
            throw new BadRequestException("Failed to create user, try again later.");
        }

        log.info("✅ User [{}] created successfully", request.getUsername());
        return handleUserCreationResponse(response, request, usersResource, realmResource);


    }

    private String handleUserCreationResponse(Response response,
                                                   RegisterRequest request,
                                                   UsersResource usersResource,
                                                   RealmResource realmResource) {
        String userId = extractUserIdFromResponse(response);

        // Set password
        setUserPassword(usersResource.get(userId), request.getPassword());

        // Assign default role
        assignDefaultRole(usersResource.get(userId), realmResource);

        log.info("User created successfully: {} with ID: {}", request.getUsername(), userId);
        return "User created successfully. Remember to check your email for the verification link.";

    }

    private String extractUserIdFromResponse(Response response) {
        return response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
    }

    private void assignDefaultRole(UserResource userResource, RealmResource realmResource) {

        RoleRepresentation roleUser = null;

        List<RoleRepresentation> availableRoles = realmResource.roles().list();

        Optional<RoleRepresentation> roleOpt = availableRoles.stream()
                .filter(r -> keycloakProperties.getDefaultRole().equals(r.getName()))
                .findFirst();

        if (!roleOpt.isPresent()){
            log.warn("Default role 'ROLE_USER' does not exist in the realm.");
            throw new BadRequestException("There was an issue processing the default role.");
        }
        roleUser = roleOpt.get();
        userResource
                .roles()
                .realmLevel()
                .add(Collections.singletonList(roleUser));

    }

    private void setUserPassword(UserResource userResource, String password) {
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(password);
        userResource.resetPassword(passwordCred);
    }

    private UserRepresentation buildUserRepresentation(RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(request.getUsername());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setEmailVerified(false); // Require email verification

        return user;
    }

    private boolean userExists(String username, String email) {
        try {
            RealmResource realm = keycloak.serviceAccountKeycloakClient().realm(keycloakProperties.getRealm());

            // Check email
            List<UserRepresentation> usersByEmail = realm.users().search(email, 0, 1);

            // Check username
            List<UserRepresentation> usersByUsername = realm.users().search(username, true);
            if (!usersByUsername.isEmpty()) {
                return true;
            }

            return !usersByEmail.isEmpty();

        } catch (Exception e) {
            log.error("Failed to check user existence", e);
            throw new BadRequestException("User existence check failed");
        }
    }


    @Override
    public LoginResponse login(LoginRequest request) {

        try {
            // Request access token
            AccessTokenResponse tokenResponse = keycloak
                    .userKeycloakClient(
                            request.getUsername(),
                            request.getPassword())
                    .tokenManager()
                    .getAccessToken();

            return new LoginResponse(
                    tokenResponse.getToken(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getExpiresIn()
            );

        } catch (javax.ws.rs.NotAuthorizedException ex) {
            // Keycloak returned 401 → map to UnauthorizedException
            log.error("Unauthorized when trying to authenticate user: {}", request.getUsername());
            throw new BadRequestException("Invalid username or password", ex);
        } catch (Exception ex) {
            // All other unexpected errors → map to InternalServerErrorException
            log.error("Failed to authenticate user: {}", ex.getMessage(), ex);
            throw new InternalServerException(
                    "Failed to authenticate user ");
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

    @Override
    public ApiResponse logout(Authentication authentication) {

        try{
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();
            String userId = jwt.getSubject();
            keycloak.serviceAccountKeycloakClient().realm(keycloakProperties.getRealm()).users().get(userId).logout();
            return new ApiResponse(HttpStatus.OK.value(),
                    "User logged out successfully");

        }catch (Exception ex){
            log.error("Failed to logout user: {}", ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Failed to logout user: " + ex.getMessage());
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

        return new LoginResponse(
                accessToken,
                newRefreshToken,
                diffSeconds
        );
    }

    /**
     * Cache The following method to avoid unnecessary database calls
     * @param authentication
     * @return
     */
    @Override
    public ApiResponse getUserInfo(Authentication authentication) {
        try {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();

            String userId = jwt.getSubject();

            String cacheKey = "user:" + userId;

            //Check redis cache first
            UserInfoResponse cacheUserInfoResponse = (UserInfoResponse) redisTemplate.opsForValue().get(cacheKey);
            if (cacheUserInfoResponse!= null) {
                return new ApiResponse(HttpStatus.OK.value(), cacheUserInfoResponse);
            }

            //Get Data from Keycloak
            UserResource userResource = keycloak
                    .serviceAccountKeycloakClient()
                    .realm(keycloakProperties.getRealm())
                    .users()
                    .get(userId);
            UserRepresentation user = userResource.toRepresentation();
            String email = user.getEmail();
            String fullName = user.getFirstName() + " " + user.getLastName();
            String username = user.getUsername();

            Boolean isVerified = user.isEmailVerified();
            Boolean isEnabled = user.isEnabled();

            List<String> roles = new ArrayList<>();

            // ✅ Realm-level roles
            List<RoleRepresentation> realmRoles = userResource.roles().realmLevel().listEffective();
            for (RoleRepresentation role : realmRoles) {
                roles.add(role.getName());
            }

            // ✅ Client-level roles (for your client)
            String clientId = keycloak
                    .serviceAccountKeycloakClient()
                    .realm(keycloakProperties.getRealm())
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

            // Build response
            UserInfoResponse userInfoResponse = new UserInfoResponse(userId, email, fullName, username, rolesWithPrefix);

            // Store in cache (saves full ApiResponse object containing User)
            redisTemplate.opsForValue().set(cacheKey, userInfoResponse, CACHE_TTL, TimeUnit.MINUTES);


            return new ApiResponse(HttpStatus.OK.value(), userInfoResponse);

        } catch (Exception ex) {
            log.error("❌ User information could not be found [{}]: {}", authentication, ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.UNAUTHORIZED.value(),
                    "Unauthorized access.");
        }
    }

    @Override
    public ApiResponse updateUser(String userId, UpdateUserRequest request) {

        try{

            UserResource userResource = keycloak
                    .serviceAccountKeycloakClient()
                    .realm(keycloakProperties.getRealm()).users().get(userId);
            if (userResource == null) {
                return new ApiResponse(HttpStatus.NOT_FOUND.value(),
                        "User not found");
            }

            UserRepresentation user = userResource.toRepresentation();

            // Check each field and update only if non-null (or non-empty in case of collections)
            if (request.getFirstName() != null && !request.getFirstName().isEmpty()) {
                user.setFirstName(request.getFirstName());
            }

            if (request.getLastName() != null && !request.getLastName().isEmpty()) {
                user.setLastName(request.getLastName());
            }

            // Ensure username is unique
            if (request.getUsername() != null) {
                // Check if username already exists in the realm (case-insensitive)
                List<UserRepresentation> existingUsers = keycloak
                        .serviceAccountKeycloakClient()
                        .realm(keycloakProperties.getRealm())
                        .users().search(request.getUsername(), true);
                if (!existingUsers.isEmpty()){
                    //List is not empty, so user exists
                    log.error("User already exists: {}", request.getUsername());
                    return new ApiResponse(HttpStatus.BAD_REQUEST.value(), "Username " + request.getUsername() + " already exists.");
                }
            }

            // Ensure email is unique
            if (request.getEmail() != null) {
                List<UserRepresentation> existingUsers = keycloak
                        .serviceAccountKeycloakClient()
                        .realm(keycloakProperties.getRealm())
                        .users().search(request.getEmail(), 0, 1);
                if (!existingUsers.isEmpty()){
                    //List is not empty, so user exists
                    log.error("Email already exists: {}", request.getEmail());
                    return new ApiResponse(HttpStatus.BAD_REQUEST.value(), "Email " + request.getEmail() + " already exists.");
                }
            }

            if (request.getEmail() != null && !request.getEmail().isEmpty()) {
                user.setEmail(request.getEmail());
            }

            if (request.getUsername() != null && !request.getUsername().isEmpty()) {
                user.setUsername(request.getUsername());
            }

            if (request.getPhoneNumber() != null && !request.getPhoneNumber().isEmpty()) {
                Map<String, List<String>> attributes = user.getAttributes();
                if (attributes == null) {
                    attributes = new HashMap<>();
                }
                attributes.put("phoneNumber", Collections.singletonList(request.getPhoneNumber()));
                user.setAttributes(attributes);
            }

            if (request.getRoles() != null && !request.getRoles().isEmpty()) {
                RealmResource realmResource = keycloak
                        .serviceAccountKeycloakClient()
                        .realm(keycloakProperties.getRealm());

                // Fetch all available roles in the realm
                List<RoleRepresentation> availableRoles = realmResource.roles().list();
                Set<String> availableRoleNames = availableRoles.stream()
                        .map(RoleRepresentation::getName)
                        .collect(Collectors.toSet());

                List<String> requestedRoles = request.getRoles();

                // Identify invalid roles
                List<String> invalidRoles = requestedRoles.stream()
                        .filter(role -> !availableRoleNames.contains(role))
                        .collect(Collectors.toList());

                if (!invalidRoles.isEmpty()) {
                    // Log or throw exception depending on your use case
                    log.error("Invalid roles requested: {}", invalidRoles);
                    return new ApiResponse(HttpStatus.BAD_REQUEST.value(), "Invalid roles requested: " + invalidRoles);
                }

                // Only map valid roles
                List<RoleRepresentation> roleReps = requestedRoles.stream()
                        .map(role -> realmResource.roles().get(role).toRepresentation())
                        .collect(Collectors.toList());

                // Assign roles
                userResource.roles().realmLevel().add(roleReps);
            }

            // Always handle booleans, since they’re primitive defaults
            if (request.getEnabled()!= null) {
                user.setEnabled(request.getEnabled());
            }
            if (request.getEmailVerified() != null){
                user.setEmailVerified(request.getEmailVerified());
            }

            // Password reset must be handled separately
            if (request.getPassword() != null && !request.getPassword().isEmpty()) {

                // 🔑 Set password
                CredentialRepresentation passwordCred = new CredentialRepresentation();
                passwordCred.setTemporary(false); // false = permanent password
                passwordCred.setType(CredentialRepresentation.PASSWORD);
                passwordCred.setValue(request.getPassword()); // assume your request DTO carries password

                userResource.resetPassword(passwordCred);

            }

            CompletableFuture.runAsync(() -> {

                try{
                    String cacheKey = "user:" + userId;

                    // Update user in Keycloak
                    userResource.update(user);
                    log.info("User {} updated successfully", userId);
                    // Clear the user cache to ensure the updated user is fetched next time
                    redisTemplate.delete(userId);

                    // Get the updated user details
                    UserResource updateUserResource = keycloak
                            .serviceAccountKeycloakClient()
                            .realm(keycloakProperties.getRealm())
                            .users()
                            .get(userId);
                    UserRepresentation updatedUser = updateUserResource.toRepresentation();
                    String email = updatedUser.getEmail();
                    String fullName = updatedUser.getFirstName() + " " + updatedUser.getLastName();
                    String username = updatedUser.getUsername();

                    List<String> roles = new ArrayList<>();

                    // ✅ Realm-level roles
                    List<RoleRepresentation> realmRoles = userResource.roles().realmLevel().listEffective();
                    for (RoleRepresentation role : realmRoles) {
                        roles.add(role.getName());
                    }

                    // ✅ Client-level roles (for your client)
                    String clientId = keycloak
                            .serviceAccountKeycloakClient()
                            .realm(keycloakProperties.getRealm())
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

                    UserInfoResponse userInfoResponse = new UserInfoResponse(
                            userId,
                            email,
                            fullName,
                            username,
                            rolesWithPrefix);

                    // Store in cache (saves full ApiResponse object containing User)
                    redisTemplate.opsForValue().set(cacheKey, userInfoResponse, CACHE_TTL, TimeUnit.MINUTES);

                    log.info("Redis User {} updated successfully", userId);

                }catch (Exception e){
                    Thread.currentThread().interrupt();
                }

            });



            return new ApiResponse(HttpStatus.OK.value(),
                    "User updated successfully");

        }catch (Exception ex){

            log.error("Failed to update user: {}", ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.BAD_REQUEST.value(),
                    "Failed to update user: " + ex.getMessage());
        }

    }

    @Override
    @Cacheable(value = "users", key = "#userId")
    public ApiResponse getUserDetails(String userId) {

        try {

            UserResource userResource = keycloak
                    .serviceAccountKeycloakClient()
                    .realm(keycloakProperties.getRealm())
                    .users()
                    .get(userId);

            UserRepresentation user = userResource.toRepresentation();
            String email = user.getEmail();
            String fullName = user.getFirstName() + " " + user.getLastName();
            String username = user.getUsername();

            Boolean isVerified = user.isEmailVerified();
            Boolean isEnabled = user.isEnabled();

            List<String> roles = new ArrayList<>();

            // ✅ Realm-level roles
            List<RoleRepresentation> realmRoles = userResource.roles().realmLevel().listEffective();
            for (RoleRepresentation role : realmRoles) {
                roles.add(role.getName());
            }

            // ✅ Client-level roles (for your client)
            String clientId = keycloak
                    .serviceAccountKeycloakClient()
                    .realm(keycloakProperties.getRealm())
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
            UserInfoResponse userInfoResponse = new UserInfoResponse(userId, email, fullName, username, rolesWithPrefix);
            return new ApiResponse(HttpStatus.OK.value(), userInfoResponse);

        }catch (Exception ex) {
            log.error("❌ The user id could not be found [{}]: {}", userId, ex.getMessage(), ex);
            return new ApiResponse(HttpStatus.NOT_FOUND.value(),
                    "The user id could not be found.");
        }


    }

}
