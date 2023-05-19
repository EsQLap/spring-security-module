package ru.virgil.security.mock

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import ru.virgil.security.InternalSecurityToken
import ru.virgil.security.firebase.FirebaseAuthenticationToken
import ru.virgil.security.service.SecurityUserService

abstract class MockSecurityContextFactory(
    private val securityUserService: SecurityUserService,
) {

    fun <Authorities : Enum<*>> createSecurityContext(
        userId: String,
        authToken: String,
        vararg authorities: Authorities,
    ): SecurityContext {
        val securityContext = SecurityContextHolder.createEmptyContext()
        val firebaseAuthenticationToken = FirebaseAuthenticationToken(
            authorities.map { SimpleGrantedAuthority(it.name) }.toMutableSet(),
            userId,
            authToken
        )
        val securityUser = securityUserService.registerOrLogin(firebaseAuthenticationToken)
        val internalSecurityToken = InternalSecurityToken(firebaseAuthenticationToken.authorities, securityUser)
        securityContext.authentication = internalSecurityToken
        return securityContext
    }
}
