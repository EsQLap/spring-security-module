package ru.virgil.security.firebase

import org.springframework.security.core.AuthenticationException

class FirebaseAuthorizationException : AuthenticationException {
    constructor(msg: String, cause: Throwable) : super(msg, cause)
    constructor(msg: String) : super(msg)
}
