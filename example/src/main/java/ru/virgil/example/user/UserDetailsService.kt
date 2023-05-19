package ru.virgil.example.user

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Lazy
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import ru.virgil.example.security.SecurityUserDetails
import ru.virgil.security.InternalSecurityToken
import java.util.*

@Service
class UserDetailsService(private val repository: UserDetailsRepository) {

    /**
     * Должен быть доступен только во время регистрации для мокирования, т.к. в это время [UserDetails]
     * из репозитория еще не доступны.
     * todo: создать кастомный Scope?
     */
    @get:Lazy
    @get:Bean(mocking)
    lateinit var mockingTimeUserDetails: UserDetails

    // TODO: Совместить, написать ленивую логику?
    @Lazy
    @Bean(current)
    fun getCurrentUser(): UserDetails {
        val token = SecurityContextHolder.getContext().authentication as InternalSecurityToken
        val securityUserDetails = token.principal as SecurityUserDetails
        return repository.findBySecurityUserDetails(securityUserDetails).orElseThrow()!!
    }

    companion object {

        private const val name = "user-details"
        const val current = "current-$name"
        const val mocking = "mocking-$name"
    }
}
