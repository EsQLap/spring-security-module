package ru.virgil.example.user

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import ru.virgil.example.security.SecurityUserDetails
import java.util.*

@Repository
interface UserDetailsRepository : JpaRepository<UserDetails, UUID> {

    fun findBySecurityUserDetails(securityUserDetails: SecurityUserDetails): Optional<UserDetails>
}
