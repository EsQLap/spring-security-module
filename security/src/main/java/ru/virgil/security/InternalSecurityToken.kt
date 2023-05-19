package ru.virgil.security

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import ru.virgil.security.entity.SecurityUser

class InternalSecurityToken(
    authorities: Collection<GrantedAuthority>,
    private val securityUser: SecurityUser,
) : AbstractAuthenticationToken(authorities) {

    /**
     * Авторизованный внутренний токен, который уходит вглубь системы, не должен знать авторизационных данных.
     *
     *
     * Хранит в себе ID и сам объект пользователя
     */
    init {
        isAuthenticated = true
    }

    /**
     * @return null, т.к. внутри сервера мы не должны знать никакой авторизационной информации пользователя
     */
    override fun getCredentials(): Void? = null

    override fun getPrincipal(): SecurityUser = securityUser
}
