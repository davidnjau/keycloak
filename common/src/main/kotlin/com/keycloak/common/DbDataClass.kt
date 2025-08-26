package com.keycloak.common


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
    val username: String,
    val roles: List<String>,
){
    constructor() : this("", "", "", "", arrayListOf())
}
data class ApiResponse(
    val statusCode: Int,
    val details: Any? = null,
)
data class UpdateUserRequest(
    val firstName: String? = null,
    val lastName: String? = null,
    val email: String? = null,

    val password: String? = null,
    val phoneNumber: String? = null,
    val username: String? = null,

    val roles: List<String>? = emptyList(),

    val enabled: Boolean? = true,
    val emailVerified: Boolean? = true
)