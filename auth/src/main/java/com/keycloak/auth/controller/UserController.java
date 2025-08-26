
package com.keycloak.auth.controller;

import com.keycloak.auth.*;
import com.keycloak.auth.service.KeycloakAuthService;
import com.keycloak.common.*;
import com.keycloak.common.response.ResponseWrapper;
import lombok.RequiredArgsConstructor;
import org.jboss.resteasy.spi.NotFoundException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final Keycloak keycloak; // Admin client bean
    private final KeycloakAuthService keycloakAuthService;

    /**
     * Retrieves the current user's information based on the authentication token.
     * 
     * This endpoint fetches the user details of the authenticated user using the
     * provided authentication object. It utilizes the KeycloakAuthService to extract
     * the user information from the authentication token.
     *
     * @param authentication The Authentication object containing the user's credentials
     *                       and token information. This is typically provided by Spring
     *                       Security based on the current session or token.
     * @return ResponseEntity containing a ResponseWrapper with UserInfoResponse.
     *         The ResponseEntity will have an HTTP status of 200 (OK) if the user
     *         information is successfully retrieved. The ResponseWrapper contains
     *         the UserInfoResponse object with the user's details.
     */
    @GetMapping("/me")
    public ResponseEntity<ResponseWrapper<UserInfoResponse>> getCurrentUser(Authentication authentication) {

        UserInfoResponse response = keycloakAuthService.getUserInfo(authentication); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    /**
     * Retrieves user information by user ID.
     * 
     * This endpoint fetches the user details for a specific user identified by their user ID.
     * It utilizes the KeycloakAuthService to retrieve the user information from Keycloak.
     *
     * @param userId The unique identifier of the user whose information is to be retrieved.
     *               This is extracted from the path variable in the URL.
     * @return ResponseEntity containing a ResponseWrapper with UserInfoResponse.
     *         The ResponseEntity will have an HTTP status of 200 (OK) if the user
     *         information is successfully retrieved. The ResponseWrapper contains
     *         the UserInfoResponse object with the user's details.
     */
    @GetMapping("/{userId}")
    public ResponseEntity<ResponseWrapper<UserInfoResponse>> getUserById(@PathVariable("userId") String userId) {
        UserInfoResponse response = keycloakAuthService.getUserDetails(userId); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
    
    /**
     * Refreshes the user's authentication token.
     * 
     * This endpoint allows a user to obtain a new access token using their refresh token.
     * It utilizes the KeycloakAuthService to process the token refresh request.
     *
     * @param refreshTokenDtO A RefreshTokenDtO object containing the refresh token and any
     *                        other necessary information for token refresh. This is
     *                        extracted from the request body.
     * @return ResponseEntity containing a ResponseWrapper with LoginResponse.
     *         The ResponseEntity will have an HTTP status of 200 (OK) if the token
     *         is successfully refreshed. The ResponseWrapper contains the LoginResponse
     *         object with the new access token and related information.
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<ResponseWrapper<LoginResponse>> refreshToken(@RequestBody RefreshTokenDtO refreshTokenDtO) {
        LoginResponse response = keycloakAuthService.refreshToken(refreshTokenDtO);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
    
    /**
     * Logs out the currently authenticated user.
     * 
     * This endpoint handles the user logout process by invalidating the current session
     * and revoking the associated tokens. It utilizes the KeycloakAuthService to perform
     * the logout operation.
     *
     * @param authentication The Authentication object containing the user's credentials
     *                       and token information. This is typically provided by Spring
     *                       Security based on the current session or token.
     * @return ResponseEntity containing a ResponseWrapper with a String message.
     *         The ResponseEntity will have an HTTP status of 200 (OK) if the logout
     *         is successful. The ResponseWrapper contains a String message indicating
     *         the result of the logout operation.
     */
    @GetMapping("/logout")
    public ResponseEntity<ResponseWrapper<String>> logout(Authentication authentication) {
        String response = keycloakAuthService.logout(authentication); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
    
    /**
     * Updates user information for a specific user.
     * 
     * This endpoint allows updating the details of a user identified by their user ID.
     * It utilizes the KeycloakAuthService to process the update request and modify
     * the user's information in Keycloak.
     *
     * @param userId The unique identifier of the user whose information is to be updated.
     *               This is extracted from the path variable in the URL.
     * @param request An UpdateUserRequest object containing the updated user information.
     *                This is extracted from the request body and should include the fields
     *                to be updated.
     * @return ResponseEntity containing a ResponseWrapper with a String message.
     *         The ResponseEntity will have an HTTP status of 200 (OK) if the user
     *         information is successfully updated. The ResponseWrapper contains
     *         a String message indicating the result of the update operation.
     */
    @PutMapping("/update-user/{userId}")
    public ResponseEntity<ResponseWrapper<String>> updateUser(@PathVariable("userId") String userId, @RequestBody UpdateUserRequest request) {
        String response = keycloakAuthService.updateUser(userId, request); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
}
