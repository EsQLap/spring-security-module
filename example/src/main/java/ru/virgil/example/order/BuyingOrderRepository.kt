package ru.virgil.example.order

import org.springframework.data.domain.Pageable
import org.springframework.stereotype.Repository
import ru.virgil.example.system.entity.OwnedEntityRepository
import ru.virgil.example.truck.Truck
import ru.virgil.example.user.UserDetails
import java.util.*

@Repository
interface BuyingOrderRepository : OwnedEntityRepository<BuyingOrder> {

    fun findAllByOwner(owner: UserDetails, pageable: Pageable): List<BuyingOrder>
    fun findByOwnerAndUuid(owner: UserDetails, uuid: UUID): Optional<BuyingOrder>
    fun countAllByOwner(owner: UserDetails): Long
    fun findAllByTruck(truck: Truck, pageable: Pageable): List<BuyingOrder>
}
