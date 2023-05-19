package ru.virgil.example.truck

import org.springframework.web.bind.annotation.*
import ru.virgil.example.box.BoxDto
import ru.virgil.example.box.BoxMapper
import ru.virgil.example.box.BoxService
import ru.virgil.example.system.rest.RestValues
import java.util.*

@RestController
@RequestMapping("/truck")
class TruckController(
    private val truckService: TruckService,
    private val boxService: BoxService,
) : BoxMapper {

    @GetMapping("/{truckUuid}/box")
    fun getBoxesByTruck(
        @PathVariable truckUuid: UUID, @RequestParam(RestValues.PAGE_PARAM) page: Int,
        @RequestParam(RestValues.PAGE_SIZE_PARAM) size: Int,
    ): List<BoxDto> {
        val truck = truckService.get(truckUuid)
        val boxes = boxService.getAll(truck, page, size)
        return boxes.stream()
            .map { it.toDto() }
            .toList()
    }
}
