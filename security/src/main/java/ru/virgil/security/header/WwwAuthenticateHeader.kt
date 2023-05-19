package ru.virgil.security.header

import ru.virgil.security.entity.AuthMethods


data class WwwAuthenticateHeader(
    val authScheme: AuthMethods,
    val challenges: Map<String, String>,
)