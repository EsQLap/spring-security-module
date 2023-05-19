package ru.virgil.example.truck

import ru.virgil.example.box.Box
import ru.virgil.example.order.BuyingOrder
import ru.virgil.example.system.entity.IdentifiedEntity
import javax.persistence.CascadeType
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.OneToMany

/**
 * Это фикс поведения JPA для двусторонних связей. Проблема тянется еще с JPA 2,
 * но ее не фиксят, чтобы не сломать совместимость. Читал на StackOverflow
 */
private const val CONNECTION = "truck"

@Entity
class Truck(
    @OneToMany(cascade = [CascadeType.REMOVE], fetch = FetchType.EAGER, mappedBy = CONNECTION)
    var boxes: Set<Box> = HashSet(),
    @OneToMany(mappedBy = CONNECTION)
    val buyingOrder: Set<BuyingOrder> = HashSet(),
) : IdentifiedEntity()
