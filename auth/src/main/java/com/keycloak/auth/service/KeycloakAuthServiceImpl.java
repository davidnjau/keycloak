
package com.keycloak.auth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.keycloak.auth.*;
import com.keycloak.auth.config.KeycloakConfig;
import com.keycloak.auth.config.KeycloakProperties;
import com.keycloak.common.*;
import com.keycloak.common.exception.InternalServerException;
import com.keycloak.common.exception.UserNotFoundException;
import com.keycloak.common.validation.UserInputValidator;
import com.keycloak.common.exception.BadRequestException;
import com.keycloak.common.exception.ConflictException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
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
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

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
     * 2. Implement email verification
     * 4. Save additional user attributes / data in my own database
     */

    private final KeycloakProperties keycloakProperties;
//    private final Keycloak keycloak; // Injected as a @Bean
    private final KeycloakConfig keycloak; // Injected as a @Bean
    private final RedisTemplate<String, Object> redisTemplate;
    private final UserInputValidator userInputValidator;

    /**
     * Registers a new user in the Keycloak system.
     * 
     * This method performs the following steps:
     * 1. Validates the registration request.
     * 2. Checks if the user already exists.
     * 3. Creates a new user representation.
     * 4. Attempts to create the user in Keycloak.
     * 5. Handles the user creation response, including setting the password and assigning default roles.
     *
     * @param request The RegisterRequest object containing the user's registration details.
     * @return A String message indicating the result of the registration process.
     * @throws BadRequestException If the registration request is invalid or the user creation fails.
     * @throws ConflictException If a user with the same username or email already exists.
     */
    @Override
    @Transactional(rollbackFor = BadRequestException.class)
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


    /**
     * Handles the response after creating a user in Keycloak.
     * This method extracts the user ID from the response, sets the user's password,
     * assigns the default role to the user, and logs the successful creation.
     *
     * @param response The Response object from the user creation request.
     * @param request The RegisterRequest object containing the user's registration details.
     * @param usersResource The UsersResource object for accessing user-related operations.
     * @param realmResource The RealmResource object for accessing realm-related operations.
     * @return A String message confirming successful user creation and prompting for email verification.
     */
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

    /**
     * Assigns the default role to a user in Keycloak.
     *
     * This method attempts to assign the default role (as specified in keycloakProperties) to the given user.
     * If the default role doesn't exist, it removes the user and throws an exception.
     *
     * @param userResource The UserResource representing the user to whom the role will be assigned.
     * @param realmResource The RealmResource representing the Keycloak realm where the operation is performed.
     * @throws BadRequestException If the default role does not exist in the realm.
     */
    private void assignDefaultRole(UserResource userResource, RealmResource realmResource) {

        RoleRepresentation roleUser;

        List<RoleRepresentation> availableRoles = realmResource.roles().list();

        Optional<RoleRepresentation> roleOpt = availableRoles.stream()
                .filter(r -> keycloakProperties.getDefaultRole().equals(r.getName()))
                .findFirst();

        if (!roleOpt.isPresent()){
            //Remove the created user as @Transactional annotation will not cause a rollback for Keycloak. (Saga pattern)
            realmResource.users().get(userResource.toRepresentation().getId()).remove();
            log.info("User removed successfully");

            log.warn("Default role 'ROLE_USER' does not exist in the realm.");
            throw new BadRequestException("There was an issue processing the default role.");
        }
        roleUser = roleOpt.get();
        userResource
                .roles()
                .realmLevel()
                .add(Collections.singletonList(roleUser));

    }

    /**
     * Sets or resets the password for a user in Keycloak.
     *
     * This method creates a new CredentialRepresentation object with the provided password,
     * sets it as a non-temporary credential, and uses it to reset the user's password
     * through the Keycloak UserResource.
     *
     * @param userResource The UserResource object representing the user in Keycloak
     *                     whose password is to be set or reset.
     * @param password The new password to be set for the user.
     */
    private void setUserPassword(UserResource userResource, String password) {
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(password);
        userResource.resetPassword(passwordCred);
    }


    /**
     * Builds a UserRepresentation object from a RegisterRequest.
     * This method creates a new UserRepresentation with the user details provided in the RegisterRequest.
     * The user is set as enabled and email verified by default.
     *
     * @param request The RegisterRequest object containing the user's registration details.
     *                It should include username, first name, last name, and email.
     * @return A UserRepresentation object populated with the user's details,
     *         ready to be used for creating a new user in Keycloak.
     */
    private UserRepresentation buildUserRepresentation(RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(request.getUsername());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setEmailVerified(true); // Require email verification

        return user;
    }

    /**
     * Checks if a user with the given username or email already exists in the Keycloak realm.
     *
     * This method performs a defensive check for both email and username existence.
     * It first retrieves the realm resource and then searches for users matching
     * the provided email and username separately.
     *
     * @param username The username to check for existence. Can be null if only checking email.
     * @param email The email address to check for existence. Can be null if only checking username.
     * @return true if a user with the given username or email exists, false otherwise.
     *         Also returns false if the realm is not found.
     */
    private boolean userExists(String username, String email) {
        RealmResource realm = keycloak.serviceAccountKeycloakClient().realm(keycloakProperties.getRealm());
        if (realm == null) {
            log.warn("Realm '{}' not found while checking user existence", keycloakProperties.getRealm());
            return false;
        }

        // Defensive: check email existence
        List<UserRepresentation> usersByEmail = Optional.ofNullable(realm.users())
                .map(u -> u.search(email, 0, 1))
                .orElse(Collections.emptyList());

        // Defensive: check username existence
        List<UserRepresentation> usersByUsername = Optional.ofNullable(realm.users())
                .map(u -> u.search(username, true))
                .orElse(Collections.emptyList());

        // Return true if either exists
        return !usersByEmail.isEmpty() || !usersByUsername.isEmpty();

    }

    /**
     * Authenticates a user and generates a login response containing access and refresh tokens.
     *
     * This method takes a LoginRequest object, uses the provided credentials to request
     * an access token from Keycloak, and then constructs a LoginResponse object with
     * the obtained token information.
     *
     * @param request The LoginRequest object containing the user's login credentials.
     *                This object should include the username and password.
     * @return A LoginResponse object containing the access token, refresh token,
     *         and token expiration time. This response can be used for subsequent
     *         authenticated requests to the system.
     */
    @Override
    public LoginResponse login(LoginRequest request) {

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
                tokenResponse.getExpiresIn());

    }


    /**
     * Extracts user roles from the provided roles source.
     * This method handles two different formats of role data:
     * 1. Roles from JWT realm_access claim (Map<String, Object>)
     * 2. Roles directly as a List<String>
     * It filters the roles to include only those starting with "ROLE_" prefix.
     *
     * @param rolesSource The source object containing role information.
     *                    This can be either a Map<String, Object> (for JWT realm_access claim)
     *                    or a List<String> (for direct role list).
     * @return A List<String> containing all roles that start with "ROLE_" prefix.
     *         Returns an empty list if no valid roles are found or if the input is null.
     */
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

    /**
     * Refreshes an authentication token using a provided refresh token.
     *
     * This method sends a request to the Keycloak server to obtain a new access token
     * using the provided refresh token. It handles the HTTP request, processes the response,
     * and returns a new LoginResponse object with updated token information.
     *
     * @param dto A RefreshTokenDtO object containing the refresh token to be used for obtaining a new access token.
     * @return A LoginResponse object containing the new access token, refresh token, and token expiration time.
     * @throws BadRequestException If the provided refresh token is empty.
     * @throws InternalServerException If the token refresh process fails or returns invalid data.
     */
    @Override
    public LoginResponse refreshToken(RefreshTokenDtO dto) {

        String refreshToken = dto.getRefreshToken();
        if (refreshToken.isEmpty()) {
            throw new BadRequestException("Refresh token is required");
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

        if (tokenResponse == null ||!tokenResponse.containsKey("access_token")) {
            throw new InternalServerException("Failed to refresh token");
        }

        String accessToken = (String) tokenResponse.get("access_token");
        String newRefreshToken = (String) tokenResponse.get("refresh_token");

        if (accessToken == null || newRefreshToken == null) {
            throw new InternalServerException("Failed to refresh token");
        }

        DecodedJWT decodedJWT = JWT.decode(accessToken);
        return getLoginResponse(decodedJWT, accessToken, newRefreshToken);

    }

    /**
     * Logs out the authenticated user from the Keycloak realm.
     *
     * This method extracts the user ID from the JWT token in the authentication object,
     * and uses it to perform a logout operation on the Keycloak server for that specific user.
     *
     * @param authentication The Authentication object containing the user's JWT token.
     *                       This is typically obtained from the security context of the current session.
     * @return A String message confirming successful logout.
     */
    @Override
    public String logout(Authentication authentication) {

        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
        Jwt jwt = jwtAuth.getToken();
        String userId = jwt.getSubject();
        keycloak.serviceAccountKeycloakClient()
                .realm(keycloakProperties.getRealm())
                .users()
                .get(userId)
                .logout();

        return "You have been logged out successfully";
    }


    /**
     * Constructs a LoginResponse object from the provided JWT and token information.
     * This method calculates the token expiration time in seconds and creates a new LoginResponse.
     *
     * @param decodedJWT The decoded JWT containing the token's expiration information.
     * @param accessToken The new access token string.
     * @param newRefreshToken The new refresh token string.
     * @return A LoginResponse object containing the access token, refresh token, and expiration time in seconds.
     */
    @NotNull
    private static LoginResponse getLoginResponse(
            DecodedJWT decodedJWT,
            String accessToken,
            String newRefreshToken) {

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
     * Extracts and processes user roles from both realm-level and client-level in Keycloak.
     *
     * This method retrieves all effective roles for a user, including both realm-level
     * and client-level roles. It then filters these roles to include only those with
     * the "ROLE_" prefix.
     *
     * @param userResource The UserResource object representing the user in Keycloak
     *                     from which to extract roles.
     * @return A List of Strings containing all the user's roles that start with "ROLE_" prefix.
     *         This includes both realm-level and client-level roles.
     */
    private List<String> extractUserRoles(UserResource userResource) {

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

        return getUserRoles(roles);

    }

    /**
     * Retrieves user information based on the provided authentication.
     * This method extracts the user ID from the JWT token in the authentication object
     * and uses it to fetch the user's information from Keycloak.
     *
     * @param authentication The Authentication object containing the user's JWT token.
     *                       This is typically obtained from the security context of the current session.
     * @return A UserInfoResponse object containing the user's details, including ID, email,
     *         full name, username, and roles. This information is fetched from Keycloak
     *         using the user ID extracted from the JWT token.
     */
    @Override
    public UserInfoResponse getUserInfo(Authentication authentication) {

        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
        Jwt jwt = jwtAuth.getToken();

        String userId = jwt.getSubject();
        return fetchUserInfoFromKeycloak(userId);

    }

    /**
     * Fetches user information from Keycloak or Redis cache based on the provided user ID.
     * This method first checks the Redis cache for the user information. If not found in cache,
     * it retrieves the information from Keycloak and then caches it in Redis for future use.
     *
     * @param userId The unique identifier of the user whose information is to be fetched.
     *               This should be a valid Keycloak user ID.
     * @return A UserInfoResponse object containing the user's details including ID, email,
     *         full name, username, and roles.
     * @throws BadRequestException If the user is not found in Keycloak.
     */
    protected UserInfoResponse fetchUserInfoFromKeycloak(String userId) {
        String cacheKey = "user:" + userId;

        // 1. Check Redis cache
        UserInfoResponse cachedUser = (UserInfoResponse) redisTemplate.opsForValue().get(cacheKey);
        if (cachedUser != null) {
            log.info("User info fetched from Redis cache: {}", userId);
            return cachedUser;
        }

        // 2. Fetch from Keycloak if not cached
        UserResource userResource = keycloak.serviceAccountKeycloakClient()
                .realm(keycloakProperties.getRealm())
                .users()
                .get(userId);

        UserRepresentation user = userResource.toRepresentation();
        if (user == null) {
            log.error("User not found: {}", userId);
            throw new BadRequestException("User not found: " + userId);
        }

        List<String> roles = extractUserRoles(userResource);

        UserInfoResponse userInfo = new UserInfoResponse(
                userId,
                user.getEmail(),
                user.getFirstName() + " " + user.getLastName(),
                user.getUsername(),
                roles
        );

        // 3. Save in Redis with TTL (optional: 1 hour here)
        log.info("User info saved in Redis cache: {}", userId);
        redisTemplate.opsForValue().set(cacheKey, userInfo, 1, TimeUnit.HOURS);

        return userInfo;
    }

    /**
     * Updates the fields of a UserRepresentation object based on the provided UpdateUserRequest.
     * This method checks each field in the request and updates the corresponding field in the user
     * representation if a new value is provided. It also handles custom attributes like phone number.
     *
     * @param user The UserRepresentation object to be updated. This object represents the user in Keycloak.
     * @param request The UpdateUserRequest object containing the new values for the user fields.
     *                This object should contain only the fields that need to be updated.
     */
    private void updateUserFields(UserRepresentation user, UpdateUserRequest request) {
        if (StringUtils.hasText(request.getFirstName())) {
            user.setFirstName(request.getFirstName());
        }
        if (StringUtils.hasText(request.getLastName())) {
            user.setLastName(request.getLastName());
        }
        if (StringUtils.hasText(request.getEmail())) {
            user.setEmail(request.getEmail());
        }
        if (StringUtils.hasText(request.getUsername())) {
            user.setUsername(request.getUsername());
        }
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }
        if (request.getEmailVerified() != null) {
            user.setEmailVerified(request.getEmailVerified());
        }

        // Handle custom attributes
        if (StringUtils.hasText(request.getPhoneNumber())) {
            Map<String, List<String>> attributes = user.getAttributes();
            if (attributes == null) {
                attributes = new HashMap<>();
            }
            attributes.put("phoneNumber", Collections.singletonList(request.getPhoneNumber()));
            user.setAttributes(attributes);
        }
    }

    /**
     * Updates the roles of a user in Keycloak.
     * This method validates the requested roles against available roles in the realm,
     * and then assigns the valid roles to the user.
     *
     * @param userResource The UserResource object representing the user whose roles are to be updated.
     *                     This should be obtained from the Keycloak client for the specific user.
     * @param requestedRoles A List of String representing the roles to be assigned to the user.
     *                       These roles should exist in the Keycloak realm.
     * @throws IllegalArgumentException If any of the requested roles do not exist in the realm.
     */
    private void updateUserRoles(UserResource userResource, List<String> requestedRoles) {
        RealmResource realmResource = keycloak
                .serviceAccountKeycloakClient()
                .realm(keycloakProperties.getRealm());

        // Validate roles exist
        List<RoleRepresentation> availableRoles = realmResource.roles().list();
        Set<String> availableRoleNames = availableRoles.stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toSet());

        List<String> invalidRoles = requestedRoles.stream()
                .filter(role -> !availableRoleNames.contains(role))
                .collect(Collectors.toList());

        if (!invalidRoles.isEmpty()) {
            throw new IllegalArgumentException("Invalid roles: " + invalidRoles);
        }

        // Map to role representations and assign
        List<RoleRepresentation> roleReps = requestedRoles.stream()
                .map(role -> realmResource.roles().get(role).toRepresentation())
                .collect(Collectors.toList());

        userResource.roles().realmLevel().add(roleReps);
    }

    /**
     * Updates a user's information in Keycloak based on the provided request.
     * This method performs the following operations:
     * - Validates the update request
     * - Retrieves the user from Keycloak
     * - Checks for username and email conflicts
     * - Updates user fields
     * - Updates the user in Keycloak
     * - Updates the user's password if provided
     * - Updates the user's roles if provided
     * - Asynchronously updates the user cache
     *
     * @param userId The unique identifier of the user to be updated. This should be a valid Keycloak user ID.
     * @param request An UpdateUserRequest object containing the fields to be updated.
     *                This can include username, email, password, roles, and other user attributes.
     * @return A String message indicating the success of the update operation.
     * @throws UserNotFoundException If the specified user is not found in Keycloak.
     * @throws ConflictException If the requested username or email already exists for another user.
     */
    @Override
    public String updateUser(String userId, UpdateUserRequest request) {

        log.info("Updating user: {}", userId);
        userInputValidator.validateUpdateRequest(request);

        UserResource userResource = keycloak
                .serviceAccountKeycloakClient()
                .realm(keycloakProperties.getRealm())
                .users()
                .get(userId);

        UserRepresentation user = userResource.toRepresentation();
        if (user == null) {
            throw new UserNotFoundException("User not found: " + userId);
        }

        // Check if user already exists

        String userName = request.getUsername();
        String email = request.getEmail();

        if (StringUtils.hasText(userName)){
            if (!user.getUsername().equals(userName)) {
                if (userExists(userName, null)) {
                    log.warn("Username already exists {}", userName);
                    throw new ConflictException("Username already exists");
                }
            }
        }

        if (StringUtils.hasText(email)){
            if (!user.getEmail().equals(email)) {
                if (userExists(null, email)) {
                    log.warn("Email already exists {}", email);
                    throw new ConflictException("Email already exists");
                }
            }
        }

        // Update user fields
        updateUserFields(user, request);

        // Update user in Keycloak
        userResource.update(user);

        // Handle password update separately
        if (StringUtils.hasText(request.getPassword())) {
            // Set password
            setUserPassword(userResource, request.getPassword());
        }

        // Handle role updates
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            updateUserRoles(userResource, request.getRoles());
        }

        // Async cache update
        CompletableFuture.runAsync(() -> updateUserCache(userId))
                .exceptionally(throwable -> {
                    log.error("Failed to update user cache for: {}", userId, throwable);
                    return null;
                });

        log.info("User updated successfully: {}", userId);

        return "User updated successfully";

    }

    /**
     * Updates the cache for a specific user by deleting the existing cache entry and fetching fresh data from Keycloak.
     * This method ensures that the cached user information is up-to-date after any modifications to the user's data.
     *
     * @param userId The unique identifier of the user whose cache needs to be updated.
     *               This should be a valid Keycloak user ID.
     */
    private void updateUserCache(String userId) {
        log.info("Deleting user cache: {}", userId);
        redisTemplate.delete(userId);
        // Store in cache (saves full ApiResponse object containing User)
        fetchUserInfoFromKeycloak(userId);
    }


    /**
     * Retrieves detailed information about a user from Keycloak based on their user ID.
     * This method delegates the actual fetching of user information to the fetchUserInfoFromKeycloak method,
     * which handles caching and retrieval of user details from Keycloak.
     *
     * @param userId The unique identifier of the user in Keycloak. This should be a valid Keycloak user ID.
     * @return A UserInfoResponse object containing detailed information about the user,
     *         including their ID, email, full name, username, and roles.
     * @throws UserNotFoundException if the user with the given ID is not found in Keycloak.
     * @throws BadRequestException if there's an issue retrieving the user information from Keycloak.
     */
    @Override
    public UserInfoResponse getUserDetails(String userId) {
        return fetchUserInfoFromKeycloak(userId);
    }

}
