package ru.virgil.security.firebase

import com.google.common.truth.Truth
import com.google.firebase.auth.FirebaseAuthException
import com.google.firebase.auth.FirebaseToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.stereotype.Component
import ru.virgil.security.InternalSecurityToken
import ru.virgil.security.entity.SecurityUser
import ru.virgil.security.service.SecurityUserService


@Component
class FirebaseAuthorizationProvider(
    private val firebaseService: FirebaseService,
    private val securityUserService: SecurityUserService,
) : AuthenticationProvider {

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val firebaseAuthenticationToken = authentication as FirebaseAuthenticationToken
        val firebaseToken: FirebaseToken
        try {
            firebaseToken = firebaseService.decodeToken(firebaseAuthenticationToken.credentials.toString())
            Truth.assertThat(firebaseAuthenticationToken.principal).isEqualTo(firebaseToken.uid)
        } catch (e: FirebaseAuthException) {
            throw FirebaseAuthorizationException("Firebase Service doesn't accept your credentials", e)
        } catch (e: AssertionError) {
            throw FirebaseAuthorizationException("Firebase Service doesn't accept your credentials", e)
        }
        val securityUser = securityUserService.registerOrLogin(authentication)
        return convertToInternalToken(authentication, securityUser)
    }

    private fun convertToInternalToken(authentication: Authentication, securityUser: SecurityUser): Authentication =
        InternalSecurityToken(authentication.authorities, securityUser)

    override fun supports(authentication: Class<*>): Boolean =
        FirebaseAuthenticationToken::class.java.isAssignableFrom(authentication)
}
