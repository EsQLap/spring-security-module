package ru.virgil.example.system.dto

import java.util.*

interface IdentifiedDto : Dto {

    var uuid: UUID?
}
