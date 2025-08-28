package com.keycloak.common.validation;

import com.keycloak.common.*;
import com.keycloak.common.exception.BadRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * Comprehensive input validation for user-related operations
 *
 * This validator ensures all user inputs meet security and business requirements
 * before processing by the Keycloak service.
 */
@Component
@Slf4j
public class UserInputValidator {

    // Regex patterns for validation
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );

    private static final Pattern USERNAME_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._-]{3,30}$"
    );

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "^\\+?[1-9]\\d{1,14}$"
    );

    private static final Pattern NAME_PATTERN = Pattern.compile(
            "^[a-zA-Z\\s'-]{1,50}$"
    );

    // Constants
    private static final int MIN_USERNAME_LENGTH = 3;
    private static final int MAX_USERNAME_LENGTH = 30;
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final int MAX_NAME_LENGTH = 50;
    private static final int MAX_EMAIL_LENGTH = 100;

    /**
     * Validates user registration request
     *
     * @param request the registration request to validate
     * @throws BadRequestException if validation fails
     */
    public void validateRegistrationRequest(RegisterRequest request) {
        log.debug("Validating registration request for username: {}", request.getUsername());

        validateUsername(request.getUsername());
        validateEmail(request.getEmail());
        validatePassword(request.getPassword());
        validateName(request.getFirstName(), "First name");
        validateName(request.getLastName(), "Last name");

        // Additional business rules
        validateNoSqlInjection(request.getUsername());
        validateNoXssAttempts(request.getFirstName(), request.getLastName());

        log.debug("Registration request validation passed for: {}", request.getUsername());
    }

    /**
     * Validates user login request
     *
     * @param request the login request to validate
     * @throws BadRequestException if validation fails
     */
    public void validateLoginRequest(LoginRequest request) {
        log.debug("Validating login request");

        if (request == null) {
            throw new BadRequestException("Login request cannot be null");
        }

        if (!StringUtils.hasText(request.getUsername())) {
            throw new BadRequestException("Username is required");
        }

        if (!StringUtils.hasText(request.getPassword())) {
            throw new BadRequestException("Password is required");
        }

        // Basic length checks to prevent buffer overflow attempts
        if (request.getUsername().length() > MAX_USERNAME_LENGTH) {
            throw new BadRequestException("Username is too long");
        }

        if (request.getPassword().length() > MAX_PASSWORD_LENGTH) {
            throw new BadRequestException("Password is too long");
        }

        validateNoSqlInjection(request.getUsername());

        log.debug("Login request validation passed");
    }

    /**
     * Validates user update request
     *
     * @param request the update request to validate
     * @throws BadRequestException if validation fails
     */
    public void validateUpdateRequest(UpdateUserRequest request) {
        log.debug("Validating update request");

        if (request == null) {
            throw new BadRequestException("Update request cannot be null");
        }

        // Validate only non-null fields
        if (StringUtils.hasText(request.getUsername())) {
            validateUsername(request.getUsername());
            validateNoSqlInjection(request.getUsername());
        }

        if (StringUtils.hasText(request.getEmail())) {
            validateEmail(request.getEmail());
        }

        if (StringUtils.hasText(request.getPassword())) {
            validatePassword(request.getPassword());
        }

        if (StringUtils.hasText(request.getFirstName())) {
            validateName(request.getFirstName(), "First name");
            validateNoXssAttempts(request.getFirstName());
        }

        if (StringUtils.hasText(request.getLastName())) {
            validateName(request.getLastName(), "Last name");
            validateNoXssAttempts(request.getLastName());
        }

        if (StringUtils.hasText(request.getPhoneNumber())) {
            validatePhoneNumber(request.getPhoneNumber());
        }

        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            validateRoles(request.getRoles());
        }

        log.debug("Update request validation passed");
    }

    /**
     * Validates username format and constraints
     */
    private void validateUsername(String username) {
        if (!StringUtils.hasText(username)) {
            throw new BadRequestException("Username is required");
        }

        if (username.length() < MIN_USERNAME_LENGTH || username.length() > MAX_USERNAME_LENGTH) {
            throw new BadRequestException(
                    String.format("Username must be between %d and %d characters",
                            MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)
            );
        }

        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new BadRequestException(
                    "Username can only contain letters, numbers, dots, underscores, and hyphens"
            );
        }

        // Check for reserved usernames
        if (isReservedUsername(username)) {
            throw new BadRequestException("Username is reserved and cannot be used");
        }
    }

    /**
     * Validates email format and constraints
     */
    private void validateEmail(String email) {
        if (!StringUtils.hasText(email)) {
            throw new BadRequestException("Email is required");
        }

        if (email.length() > MAX_EMAIL_LENGTH) {
            throw new BadRequestException("Email is too long");
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new BadRequestException("Invalid email format");
        }

        // Check for disposable email domains (optional)
        if (isDisposableEmail(email)) {
            throw new BadRequestException("Disposable email addresses are not allowed");
        }
    }

    /**
     * Validates password strength and constraints
     */
    private void validatePassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new BadRequestException("Password is required");
        }

        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new BadRequestException(
                    String.format("Password must be at least %d characters long", MIN_PASSWORD_LENGTH)
            );
        }

        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new BadRequestException("Password is too long");
        }

        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new BadRequestException(
                    "Password must contain at least one uppercase letter, one lowercase letter, " +
                            "one digit, and one special character (@$!%*?&)"
            );
        }

        // Check for common weak passwords
        if (isCommonPassword(password)) {
            throw new BadRequestException("Password is too common. Please choose a stronger password");
        }
    }

    /**
     * Validates name fields (first name, last name)
     */
    private void validateName(String name, String fieldName) {
        if (!StringUtils.hasText(name)) {
            throw new BadRequestException(fieldName + " is required");
        }

        if (name.length() > MAX_NAME_LENGTH) {
            throw new BadRequestException(fieldName + " is too long");
        }

        if (!NAME_PATTERN.matcher(name).matches()) {
            throw new BadRequestException(
                    fieldName + " can only contain letters, spaces, apostrophes, and hyphens"
            );
        }
    }

    /**
     * Validates phone number format
     */
    private void validatePhoneNumber(String phoneNumber) {
        if (!PHONE_PATTERN.matcher(phoneNumber).matches()) {
            throw new BadRequestException("Invalid phone number format");
        }
    }

    /**
     * Validates role names
     */
    private void validateRoles(java.util.List<String> roles) {
        for (String role : roles) {
            if (!StringUtils.hasText(role)) {
                throw new BadRequestException("Role name cannot be empty");
            }

            if (role.length() > 50) {
                throw new BadRequestException("Role name is too long: " + role);
            }

            // Role names should follow a specific pattern
            if (!role.matches("^ROLE_[A-Z_]+$")) {
                throw new BadRequestException("Invalid role format: " + role);
            }
        }
    }

    /**
     * Checks for potential SQL injection attempts in the given input string.
     *
     * This method performs a basic check for common SQL keywords and patterns
     * that might indicate an SQL injection attempt. It converts the input to
     * lowercase and searches for predefined SQL-related keywords.
     *
     * @param input The string to be checked for potential SQL injection attempts.
     *              If null, the method returns immediately without performing any checks.
     * @throws BadRequestException if a potential SQL injection attempt is detected.
     *         The exception message will be "Invalid characters detected in input".
     */
    private void validateNoSqlInjection(String input) {
        if (input == null) return;

        String lowerInput = input.toLowerCase();
        String[] sqlKeywords = {
                "select", "insert", "update", "delete", "drop", "create", "alter",
                "union", "script", "exec", "execute", "--", "/*", "*/", "xp_", "sp_"
        };

        for (String keyword : sqlKeywords) {
            if (lowerInput.contains(keyword)) {
                log.warn("Potential SQL injection attempt detected: {}", input);
                throw new BadRequestException("Invalid characters detected in input");
            }
        }
    }

    /**
     * Validates input strings for potential Cross-Site Scripting (XSS) attempts.
     *
     * This method checks each input string against a predefined list of XSS patterns.
     * If any of the patterns are found in the input, it logs a warning and throws an exception.
     * The check is case-insensitive.
     *
     * @param inputs Variable number of input strings to be validated against XSS patterns.
     *               Each input is checked individually. Null inputs are skipped.
     * @throws BadRequestException if a potential XSS attempt is detected in any of the inputs.
     *                             The exception message will be "Invalid characters detected in input".
     */
    private void validateNoXssAttempts(String... inputs) {
        for (String input : inputs) {
            if (input == null) continue;

            String lowerInput = input.toLowerCase();
            String[] xssPatterns = {
                    "<script", "</script>", "javascript:", "onload=", "onerror=",
                    "onclick=", "onmouseover=", "alert(", "document.cookie"
            };

            for (String pattern : xssPatterns) {
                if (lowerInput.contains(pattern)) {
                    log.warn("Potential XSS attempt detected: {}", input);
                    throw new BadRequestException("Invalid characters detected in input");
                }
            }
        }
    }


    /**
     * Checks if a given username is reserved.
     *
     * This method compares the provided username against a predefined list of
     * reserved usernames. It checks for exact matches and also for usernames
     * that start with a reserved name followed by an underscore.
     *
     * @param username The username to be checked. The comparison is case-insensitive.
     * @return {@code true} if the username is reserved (either an exact match or
     *         starts with a reserved name followed by an underscore), {@code false} otherwise.
     */
    private boolean isReservedUsername(String username) {
        String[] reservedUsernames = {
                "admin", "administrator", "root", "system", "service", "support",
                "help", "info", "mail", "email", "user", "guest", "anonymous",
                "keycloak", "auth", "oauth", "api", "www", "ftp", "smtp", "pop3"
        };

        String lowerUsername = username.toLowerCase();
        for (String reserved : reservedUsernames) {
            if (lowerUsername.equals(reserved) || lowerUsername.startsWith(reserved + "_")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the provided email address is from a known disposable email provider.
     *
     * This method performs a simplified check against a predefined list of common
     * disposable email domains. In a production environment, it's recommended to use
     * a more comprehensive list or a third-party service for better accuracy.
     *
     * @param email The email address to be checked. The method extracts the domain
     *              part of the email for comparison.
     * @return {@code true} if the email's domain matches any known disposable email
     *         provider in the predefined list, {@code false} otherwise.
     */
    private boolean isDisposableEmail(String email) {
        // This is a simplified check. In production, you might want to use
        // a comprehensive list or a service like Kickbox, ZeroBounce, etc.
        String[] disposableDomains = {
                "10minutemail.com", "tempmail.org", "guerrillamail.com",
                "mailinator.com", "throwaway.email", "temp-mail.org"
        };

        String domain = email.substring(email.lastIndexOf("@") + 1).toLowerCase();
        for (String disposable : disposableDomains) {
            if (domain.equals(disposable)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a given password is commonly used and therefore considered weak.
     *
     * This method compares the provided password against a predefined list of
     * common passwords. In a production environment, it's recommended to use a more
     * comprehensive list or a service like HaveIBeenPwned for better security.
     *
     * @param password The password to be checked for commonness.
     * @return {@code true} if the password is found in the list of common passwords,
     *         {@code false} otherwise.
     */
    private boolean isCommonPassword(String password) {
        // This is a simplified check. In production, you might want to use
        // a comprehensive list of common passwords or a service like HaveIBeenPwned
        String[] commonPasswords = {
                "password", "123456", "password123", "admin", "qwerty",
                "letmein", "welcome", "monkey", "dragon", "master",
                "Password1", "Password123", "Admin123", "Welcome123"
        };

        for (String common : commonPasswords) {
            if (password.equals(common)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sanitizes input by removing potentially harmful characters and HTML tags.
     *
     * This method performs the following sanitization steps:
     * 1. Removes all HTML tags.
     * 2. Removes specific potentially harmful characters (< > " ' &).
     * 3. Trims leading and trailing whitespace.
     *
     * @param input The string to be sanitized. If null, the method returns null without performing any sanitization.
     * @return A sanitized version of the input string with potentially harmful content removed,
     *         or null if the input was null.
     */
    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        // Remove HTML tags and potentially harmful characters
        return input.replaceAll("<[^>]*>", "")
                .replaceAll("[<>\"'&]", "")
                .trim();
    }

    /**
     * Validates that the input string does not exceed a specified maximum length.
     *
     * This method checks if the length of the input string is within the specified maximum length.
     * If the input exceeds the maximum length, a BadRequestException is thrown with a formatted error message.
     *
     * @param input     the input string to be validated. If null, no validation is performed.
     * @param maxLength the maximum allowed length for the input string.
     * @param fieldName the name of the field being validated, used in the error message if validation fails.
     * @throws BadRequestException if the input string length exceeds the specified maximum length.
     */
    public void validateMaxLength(String input, int maxLength, String fieldName) {
        if (input != null && input.length() > maxLength) {
            throw new BadRequestException(
                    String.format("%s cannot exceed %d characters", fieldName, maxLength)
            );
        }
    }

    /**
     * Validates that a required field is not empty or blank.
     *
     * This method checks if the given input string has any text content.
     * If the input is null, empty, or contains only whitespace characters,
     * it throws a BadRequestException with a message indicating that the field is required.
     *
     * @param input     the input string to be validated
     * @param fieldName the name of the field being validated, used in the error message
     * @throws BadRequestException if the input is null, empty, or contains only whitespace
     */
    public void validateRequired(String input, String fieldName) {
        if (!StringUtils.hasText(input)) {
            throw new BadRequestException(fieldName + " is required");
        }
    }
}
