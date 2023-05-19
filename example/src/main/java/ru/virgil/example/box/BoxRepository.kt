package ru.virgil.example.box

import org.springframework.data.domain.Pageable
import org.springframework.stereotype.Repository
import ru.virgil.example.system.entity.OwnedEntityRepository
import ru.virgil.example.truck.Truck
import ru.virgil.example.user.UserDetails
import java.util.*

@Repository
interface BoxRepository : OwnedEntityRepository<Box> {

    @Deprecated("Use Deleted False")
    fun findByOwnerAndUuid(owner: UserDetails, uuid: UUID): Optional<Box>
    fun findByOwnerAndUuidAndDeletedIsFalse(owner: UserDetails, uuid: UUID): Optional<Box>

    @Deprecated("Use Deleted False")
    fun findAllByOwner(owner: UserDetails, pageable: Pageable): List<Box>
    fun findAllByOwnerAndDeletedIsFalse(owner: UserDetails, pageable: Pageable): List<Box>

    @Deprecated("Use Deleted False")
    fun findAllByOwnerAndTruck(owner: UserDetails, truck: Truck, pageable: Pageable): List<Box>
    fun findAllByOwnerAndTruckAndDeletedIsFalse(owner: UserDetails, truck: Truck, pageable: Pageable): List<Box>

    @Deprecated("Use Deleted False")
    fun countAllByOwner(owner: UserDetails): Long
    fun countAllByOwnerAndDeletedIsFalse(owner: UserDetails): Long

    @Deprecated("Use Deleted False")
    fun findAllByOwnerAndType(owner: UserDetails, boxType: BoxType): List<Box>
    fun findAllByOwnerAndTypeAndDeletedIsFalse(owner: UserDetails, boxType: BoxType): List<Box>
}
