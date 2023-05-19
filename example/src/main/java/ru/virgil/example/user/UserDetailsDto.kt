package ru.virgil.example.user

import ru.virgil.example.system.dto.IdentifiedDto
import java.time.LocalDateTime
import java.util.*

class UserDetailsDto(
    override var createdAt: LocalDateTime?,
    override var updatedAt: LocalDateTime?,
    override var uuid: UUID?,
    var name: String? = null,
) : IdentifiedDto
