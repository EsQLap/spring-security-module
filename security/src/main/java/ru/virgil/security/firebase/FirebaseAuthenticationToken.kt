package ru.virgil.security.firebase

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class FirebaseAuthenticationToken(
    authorities: Collection<GrantedAuthority>,
    private val firebaseUid: String,
    private val firebaseAuthToken: String,
) : AbstractAuthenticationToken(authorities) {

    /**
     * Внешний токен, который содержит данные для авторизации Firebase.
     * В провайдере должен быть превращен в [InternalSecurityToken]
     *
     * @param authorities       the collection of [GrantedAuthority]s for the principal
     * represented by this authentication object.
     * @param firebaseUid       Идентификатор пользователя Firebase
     * @param firebaseAuthToken Токен для авторизации Firebase
     */
    init {
        isAuthenticated = false
    }

    override fun getCredentials(): Any = firebaseAuthToken

    override fun getPrincipal(): Any = firebaseUid
}
