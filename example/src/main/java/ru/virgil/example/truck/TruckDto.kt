package ru.virgil.example.truck

import ru.virgil.example.system.dto.IdentifiedDto
import java.time.LocalDateTime
import java.util.*

data class TruckDto(
    override var createdAt: LocalDateTime?,
    override var updatedAt: LocalDateTime?,
    override var uuid: UUID?,
    var boxesCount: Int?,
) : IdentifiedDto
