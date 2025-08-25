package com.keycloak.auth

data class RegisterRequest(
    val username: String,
    val email: String,
    val password: String,
    val firstName: String,
    val lastName: String,
){
    constructor() : this("", "", "", "", "")
}

data class LoginRequest(
    val username: String,
    val password: String,
){
    constructor() : this("", "")
}
data class RefreshTokenDtO(
    val refreshToken: String,
){
    constructor() : this("")
}

data class TokenResponse(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String,
    val expiresIn: String,
){
    constructor() : this("", "", "", "")
}

data class LoginResponse(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Long,
){
    constructor() : this("", "", 0)
}
data class UserInfoResponse(
    val userId: String,
    val email: String,
    val fullName: String,
    val roles: List<String>,
){
    constructor() : this("", "", "", arrayListOf())
}
data class ApiResponse(
    val statusCode: Int,
    val details: Any? = null,
)