package ru.virgil.example.box

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
import java.util.*

@Lazy
@Component
class BoxMocker(
    @Lazy
    @Qualifier(UserDetailsService.mocking)
    private val ownerProvider: ObjectProvider<UserDetails>,
    private val faker: Faker,
    private val truckRepository: TruckRepository,
    private val boxRepository: BoxRepository,
) : BaseMocker() {

    private val owner by lazy { ownerProvider.getObject() }

    companion object {

        private const val name = "box"
        const val new = "new-$name"
        const val random = "random-$name"
    }

    @Bean(new)
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    fun new(): Box {
        val truck = truckRepository.findPriorityOrGetRandom { it.boxes.isEmpty() }
        return Box(
            owner,
            BoxType.values().random(),
            truck,
            faker.chuckNorris().fact(),
            Random().nextInt(500),
            Random().nextFloat(20f, 50f),
        )
    }

    @Bean(random)
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    fun random(): Box = boxRepository.findAllByOwner(owner).random()
}
