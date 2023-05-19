package ru.virgil.example.box

import org.springframework.stereotype.Component

// TODO: Можно превратить в объект?
@Component
class BoxSecurity {

    fun hasWeapon(boxDto: BoxDto): Boolean = boxDto.type === BoxType.WEAPON
}
