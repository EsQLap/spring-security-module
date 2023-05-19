package ru.virgil.example.user

import ru.virgil.example.security.SecurityUserDetails
import ru.virgil.example.system.entity.IdentifiedEntity
import ru.virgil.utils.base.entity.Identified
import ru.virgil.utils.base.entity.Timed
import javax.persistence.Entity
import javax.persistence.OneToOne

@Entity
class UserDetails(
    @OneToOne
    private val securityUserDetails: SecurityUserDetails,
    var name: String? = null,
) : IdentifiedEntity(), Identified, Timed
