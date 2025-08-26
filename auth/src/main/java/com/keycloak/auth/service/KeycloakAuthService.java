
package com.keycloak.auth.service;

import com.keycloak.auth.*;
import com.keycloak.common.*;
import org.springframework.security.core.Authentication;

/**
 * Service interface for Keycloak authentication operations.
 */
public interface KeycloakAuthService {

    /**
     * Registers a new user in the system.
     *
     * @param request The registration details of the user.
     * @return A String containing the ID of the newly registered user.
     */
    String registerUser(RegisterRequest request);

    /**
     * Authenticates a user and creates a new session.
     *
     * @param request The login credentials of the user.
     * @return A LoginResponse object containing authentication details and tokens.
     */
    LoginResponse login(LoginRequest request);

    /**
     * Retrieves the information of the currently authenticated user.
     *
     * @param authentication The current authentication object.
     * @return A UserInfoResponse object containing the user's details.
     */
    UserInfoResponse getUserInfo(Authentication authentication);

    /**
     * Retrieves the details of a specific user by their ID.
     *
     * @param userId The ID of the user whose details are to be retrieved.
     * @return A UserInfoResponse object containing the user's details.
     */
    UserInfoResponse getUserDetails(String userId);

    /**
     * Refreshes the authentication token for a user.
     *
     * @param refreshTokenDtO The DTO containing the refresh token.
     * @return A LoginResponse object containing the new authentication details and tokens.
     */
    LoginResponse refreshToken(RefreshTokenDtO refreshTokenDtO);

    /**
     * Logs out the currently authenticated user.
     *
     * @param authentication The current authentication object.
     * @return A String indicating the result of the logout operation.
     */
    String logout(Authentication authentication);

    /**
     * Updates the details of a specific user.
     *
     * @param userId The ID of the user whose details are to be updated.
     * @param request The UpdateUserRequest containing the new user details.
     * @return A String indicating the result of the update operation.
     */
    String updateUser(String userId, UpdateUserRequest request);
}
