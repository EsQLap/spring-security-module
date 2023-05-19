package ru.virgil.example.box

import ru.virgil.example.system.entity.OwnedEntity
import ru.virgil.example.truck.Truck
import ru.virgil.example.user.UserDetails
import javax.persistence.*

@Entity
class Box(
    owner: UserDetails,
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    var type: BoxType = BoxType.USUAL,
    @ManyToOne(cascade = [CascadeType.REMOVE])
    var truck: Truck,
    var description: String,
    var price: Int = 0,
    var weight: Float = 0f,
) : OwnedEntity(owner)
