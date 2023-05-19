package ru.virgil.example.system.entity

import java.util.*
import javax.persistence.GeneratedValue
import javax.persistence.Id
import javax.persistence.MappedSuperclass

// TODO: Переместить в базовый модуль
@MappedSuperclass
abstract class IdentifiedEntity(
    @GeneratedValue
    @Id
    var uuid: UUID = UUID.randomUUID(),
) : BaseEntity()
