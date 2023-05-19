package ru.virgil.security.entity


data class AuthRecord(
    val principal: String?,
    val credentials: String?,
)
