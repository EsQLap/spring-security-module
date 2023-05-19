package ru.virgil.utils.base.entity

interface Owned<Owner : Identified> {

    var owner: Owner
}
