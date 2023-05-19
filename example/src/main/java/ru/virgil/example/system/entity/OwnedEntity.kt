package ru.virgil.example.system.entity

import ru.virgil.example.user.UserDetails
import javax.persistence.ManyToOne
import javax.persistence.MappedSuperclass

// TODO: Переместить в базовый модуль в виде интерфейса
@MappedSuperclass
abstract class OwnedEntity(
    @ManyToOne
    var owner: UserDetails,
) : IdentifiedEntity()
