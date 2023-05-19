package ru.virgil.example.box

import ru.virgil.example.truck.Truck
import ru.virgil.example.user.UserDetails

interface BoxMapper {

    fun BoxDto.toEntity(owner: UserDetails, truck: Truck): Box =
        Box(owner, type!!, truck, description!!, price!!, weight!!)

    fun Box.toDto(): BoxDto = BoxDto(uuid, createdAt, updatedAt, type, description, price, weight)

    fun Box.merge(boxDto: BoxDto): Box {
        price = boxDto.price ?: price
        type = boxDto.type ?: type
        description = boxDto.description ?: description
        weight = boxDto.weight ?: weight
        return this
    }
}
