package ru.virgil.example.system.dto

import java.time.LocalDateTime

interface Dto {

    var createdAt: LocalDateTime?
    var updatedAt: LocalDateTime?
}
