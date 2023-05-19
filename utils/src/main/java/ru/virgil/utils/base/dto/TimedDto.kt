package ru.virgil.utils.base.dto

import java.time.LocalDateTime

interface TimedDto {

    var createdAt: LocalDateTime?
    var updatedAt: LocalDateTime?
}
