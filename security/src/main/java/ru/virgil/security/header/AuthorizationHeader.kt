package ru.virgil.security.header

import ru.virgil.security.entity.AuthMethods


data class AuthorizationHeader(
    val authScheme: AuthMethods,
    val credentials: Map<String, String>,
)
