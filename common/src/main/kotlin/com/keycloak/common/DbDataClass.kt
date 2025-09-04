package com.keycloak.common

import java.math.BigDecimal


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
enum class IdentifierType {
    USER_ID,
    USERNAME,
    APPLICATION_ID
}
data class DbProduct(
    val id: String?,
    val name: String,
    val description: String,
    val oldPrice: BigDecimal,
    val oldPriceCurrency: String,
    val newPrice: BigDecimal,
    val newPriceCurrency: String,
    val quantity: Int,
    val availableQuantity: Int,
    val reservedQuantity: Int,
    val productImages: List<DbProductImage>
){
    constructor() : this(null, "", "",
        BigDecimal.ZERO, "", BigDecimal.ZERO, "",
        0, 0, 0, emptyList())
}
data class DbProductCategory(
    val id: String?,
    val name: String?,
    val description: String?,
    val path: String?,
    val parentCategoryId: String?,
){
    constructor() : this(null, null, null, null, null)
}
data class DbProductImage(
    val id: String?,
    val imageUrl: String,
    val metadata: String,
    val sortOrder: Int,
    val storageId: String,
    val isValid: Boolean,
    val productId: String
){
    constructor() : this(null, "",
        "", 0, "",
        false, "")
}
data class DBPaginatedResult(
    val count: Long,
    val currentPage: Int,
    val pageSize: Int,
    val totalPages: Int,
    val items: List<Any>
){
    constructor() : this(
        0,
        0,
        0,
        0,
        emptyList()
    )
}