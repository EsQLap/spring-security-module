package ru.virgil.security.service

import org.springframework.security.core.Authentication
import ru.virgil.security.entity.SecurityUser

interface SecurityUserService {

    fun registerOrLogin(authentication: Authentication): SecurityUser
}
