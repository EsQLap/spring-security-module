package ru.virgil.example.order

import ru.virgil.example.system.entity.OwnedEntity
import ru.virgil.example.truck.Truck
import ru.virgil.example.user.UserDetails
import javax.persistence.Entity
import javax.persistence.ManyToOne

@Entity
class BuyingOrder(
    owner: UserDetails,
    @ManyToOne
    var truck: Truck,
    var description: String?,
) : OwnedEntity(owner)
