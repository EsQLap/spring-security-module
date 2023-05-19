package ru.virgil.example.order

import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import ru.virgil.example.user.UserDetails
import ru.virgil.example.user.UserDetailsService
import java.util.*

@Service
class BuyingOrderService(
    @Qualifier(UserDetailsService.current)
    private val ownerProvider: ObjectProvider<UserDetails>,
    private val buyingOrderRepository: BuyingOrderRepository,
) {

    private val owner by lazy { ownerProvider.getObject() }

    fun getAll(page: Int, size: Int): List<BuyingOrder> =
        buyingOrderRepository.findAllByOwner(owner, PageRequest.of(page, size))

    fun get(uuid: UUID): BuyingOrder = buyingOrderRepository.findByOwnerAndUuid(owner, uuid).orElseThrow()

    fun countMy(): Long = buyingOrderRepository.countAllByOwner(owner)
}
