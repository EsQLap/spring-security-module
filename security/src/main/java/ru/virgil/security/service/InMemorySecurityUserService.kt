package ru.virgil.security.service

import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service
import ru.virgil.security.entity.BaseSecurityUser
import ru.virgil.security.entity.SecurityUser

@Service
class InMemorySecurityUserService(
    private val baseSecurityUsers: MutableSet<SecurityUser> = HashSet(),
) : SecurityUserService {

    override fun registerOrLogin(authentication: Authentication): SecurityUser = baseSecurityUsers.stream()
        .filter { (it.firebaseUserId == authentication.principal.toString()) }
        .findAny()
        .orElseGet { registerNewUser(authentication) }

    private fun registerNewUser(authentication: Authentication): SecurityUser {
        val securityUserDetails = BaseSecurityUser(
            authentication.authorities, firebaseUserId = authentication.toString()
        )
        baseSecurityUsers.add(securityUserDetails)
        return securityUserDetails
    }
}
