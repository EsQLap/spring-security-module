package ru.virgil.example.system.entity

import org.hibernate.annotations.CreationTimestamp
import org.hibernate.annotations.UpdateTimestamp
import ru.virgil.example.system.entity.LocalDateTimeExtensions.databaseTruncate
import java.time.LocalDateTime
import javax.persistence.MappedSuperclass

@MappedSuperclass
abstract class BaseEntity(
    createdAt: LocalDateTime = LocalDateTime.now(),
    updatedAt: LocalDateTime = LocalDateTime.now(),
    var deleted: Boolean = false,
) {

    @UpdateTimestamp
    var updatedAt = updatedAt
        get() = field.databaseTruncate()
        set(value) {
            field = value.databaseTruncate()
        }

    @CreationTimestamp
    var createdAt = createdAt
        get() = field.databaseTruncate()
        set(value) {
            field = value.databaseTruncate()
        }
}
