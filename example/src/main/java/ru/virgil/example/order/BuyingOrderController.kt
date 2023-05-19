package ru.virgil.example.order

import org.springframework.web.bind.annotation.*
import ru.virgil.example.system.rest.RestValues.PAGE_PARAM
import ru.virgil.example.system.rest.RestValues.PAGE_SIZE_PARAM
import ru.virgil.example.truck.TruckDto
import ru.virgil.example.truck.TruckMapper
import ru.virgil.example.truck.TruckService
import java.util.*

@RestController
@RequestMapping("/buying_order")
class BuyingOrderController(
    private val buyingOrderService: BuyingOrderService,
    private val truckService: TruckService,
) : BuyingOrderMapper, TruckMapper {

    @GetMapping
    fun getAll(@RequestParam(PAGE_PARAM) page: Int, @RequestParam(PAGE_SIZE_PARAM) size: Int): List<BuyingOrderDto> =
        buyingOrderService.getAll(page, size).stream()
            .map { it.toDto() }
            .toList()

    @GetMapping("/{uuid}")
    operator fun get(@PathVariable uuid: UUID): BuyingOrderDto {
        val buyingOrder = buyingOrderService.get(uuid)
        return buyingOrder.toDto()
    }

    @GetMapping("/{buyingOrderUuid}/truck")
    fun getTrucksByOrder(
        @PathVariable buyingOrderUuid: UUID,
        @RequestParam(PAGE_PARAM) page: Int,
        @RequestParam(PAGE_SIZE_PARAM) size: Int,
    ): List<TruckDto> {
        val buyingOrder = buyingOrderService.get(buyingOrderUuid)
        val trucks = truckService.getAll(buyingOrder, page, size)
        return trucks.stream()
            .map { it.toDto() }
            .toList()
    }
}

