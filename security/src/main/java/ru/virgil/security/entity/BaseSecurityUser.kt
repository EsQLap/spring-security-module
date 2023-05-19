package ru.virgil.security.entity

import org.springframework.security.core.GrantedAuthority


class BaseSecurityUser(
    override val authorities: Collection<GrantedAuthority>,
    override val banned: Boolean = false,
    override val firebaseUserId: String,
) : SecurityUser
