package ru.virgil.example.security

import org.springframework.context.annotation.Primary
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service
import ru.virgil.example.system.mock.Mocker
import ru.virgil.example.user.UserDetails
import ru.virgil.example.user.UserDetailsRepository
import ru.virgil.example.user.UserDetailsService
import ru.virgil.security.entity.SecurityUser
import ru.virgil.security.firebase.FirebaseAuthenticationToken
import ru.virgil.security.service.SecurityUserService
import ru.virgil.utils.Faker

@Primary
@Service
class SecurityUserDetailsService(
    private val repository: SecurityUserDetailsRepository,
    private val userDetailsService: UserDetailsService,
    private val userDetailsRepository: UserDetailsRepository,
    private val faker: Faker,
    private val mocker: Mocker,
) : SecurityUserService {

    override fun registerOrLogin(authentication: Authentication): SecurityUser {
        if (authentication !is FirebaseAuthenticationToken) {
            throw AuthenticationServiceException(
                "Wrong %s token type in %s".format(
                    authentication.javaClass.simpleName, this.javaClass.simpleName
                )
            )
        }
        return repository.findByFirebaseUserId(authentication.principal.toString())
            .orElseGet { register(authentication) }
    }

    fun register(firebaseAuthenticationToken: FirebaseAuthenticationToken): SecurityUserDetails {
        var securityUserDetails = SecurityUserDetails(
            userAuthorities = mutableSetOf(UserAuthority.ROLE_USER),
            firebaseUserId = firebaseAuthenticationToken.principal.toString()
        )
        securityUserDetails = repository.save(securityUserDetails)
        var userDetails = UserDetails(securityUserDetails)
        userDetails.name = faker.animal().name()
        userDetails = userDetailsRepository.save(userDetails)
        userDetails = mock(userDetails)
        return securityUserDetails
    }

    private fun mock(userDetails: UserDetails): UserDetails {
        userDetailsService.mockingTimeUserDetails = userDetails
        mocker.mock()
        return userDetails
    }
}
