package ru.virgil.security.entity

import org.springframework.security.core.GrantedAuthority

interface SecurityUser {

    val authorities: Collection<GrantedAuthority>
    val banned: Boolean
    val firebaseUserId: String
}
