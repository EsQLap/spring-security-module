package ru.virgil.example.system.mock


import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Lazy
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Component
import ru.virgil.example.box.Box
import ru.virgil.example.box.BoxMocker
import ru.virgil.example.box.BoxRepository
import ru.virgil.example.order.BuyingOrder
import ru.virgil.example.order.BuyingOrderMocker
import ru.virgil.example.order.BuyingOrderRepository
import ru.virgil.example.truck.Truck
import ru.virgil.example.truck.TruckMocker
import ru.virgil.example.truck.TruckRepository
import java.util.*

@Component
class Mocker(
    @Lazy
    @Qualifier(BuyingOrderMocker.new)
    private val buyingOrderMocker: ObjectProvider<BuyingOrder>,
    private val buyingOrderRepository: BuyingOrderRepository,
    @Lazy
    @Qualifier(BoxMocker.new)
    private val boxMocker: ObjectProvider<Box>,
    private val boxRepository: BoxRepository,
    @Lazy
    @Qualifier(TruckMocker.new)
    private val truckMocker: ObjectProvider<Truck>,
    private val truckRepository: TruckRepository,
) {

    fun mock() {
        mock(10, truckMocker, truckRepository)
        mock(5, buyingOrderMocker, buyingOrderRepository)
        mock(10, boxMocker, boxRepository)
    }

    protected fun <Entity> mock(
        number: Int,
        objectProvider: ObjectProvider<Entity>,
        repository: CrudRepository<Entity, UUID>,
    ) {
        val chats = ArrayList<Entity>()
        for (i in 1..number) chats.add(objectProvider.getObject())
        repository.saveAll(chats)
    }
}
