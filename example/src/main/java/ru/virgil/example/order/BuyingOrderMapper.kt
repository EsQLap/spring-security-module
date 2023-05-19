package ru.virgil.example.order

interface BuyingOrderMapper {

    fun BuyingOrder.toDto(): BuyingOrderDto = BuyingOrderDto(
        createdAt,
        updatedAt,
        uuid,
        description,
    )

    fun BuyingOrder.merge(buyingOrderDto: BuyingOrderDto): BuyingOrder {
        description = buyingOrderDto.description ?: description
        return this
    }
}
