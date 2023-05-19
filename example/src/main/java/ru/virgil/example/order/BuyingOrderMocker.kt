package ru.virgil.example.order

import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.config.ConfigurableBeanFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Lazy
import org.springframework.context.annotation.Scope
import org.springframework.stereotype.Component
import ru.virgil.example.system.mock.BaseMocker
import ru.virgil.example.truck.TruckRepository
import ru.virgil.example.user.UserDetails
import ru.virgil.example.user.UserDetailsService
import ru.virgil.utils.Faker

@Lazy
@Component
class BuyingOrderMocker(
    @Lazy
    @Qualifier(UserDetailsService.mocking)
    private val ownerProvider: ObjectProvider<UserDetails>,
    private val faker: Faker,
    private val buyingOrderRepository: BuyingOrderRepository,
    private val truckRepository: TruckRepository,
) : BaseMocker() {

    private val owner by lazy { ownerProvider.getObject() }

    companion object {

        private const val name = "buying-order"
        const val new = "new-$name"
        const val random = "random-$name"
    }

    @Bean(new)
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    fun new(): BuyingOrder {
        val truck = truckRepository.findPriorityOrGetRandom { it.buyingOrder == null }
        return BuyingOrder(owner, truck, faker.ancient().hero())
    }

    @Bean(random)
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    fun random(): BuyingOrder = buyingOrderRepository.findAllByOwner(owner).random()
}
