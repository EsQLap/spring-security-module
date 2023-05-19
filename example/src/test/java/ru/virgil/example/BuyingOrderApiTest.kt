package ru.virgil.example

import com.google.common.truth.Truth
import org.apache.http.client.utils.URIBuilder
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.ComponentScan
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import ru.virgil.example.order.BuyingOrder
import ru.virgil.example.order.BuyingOrderDto
import ru.virgil.example.order.BuyingOrderMocker
import ru.virgil.example.system.rest.RestValues.PAGE_PARAM
import ru.virgil.example.system.rest.RestValues.PAGE_SIZE_PARAM
import ru.virgil.example.truck.TruckDto
import ru.virgil.example.util.security.user.WithMockFirebaseUser
import ru.virgil.test_utils.fluent_request.RequestUtil
import java.util.*

@SpringBootTest
@AutoConfigureMockMvc
@WithMockFirebaseUser
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ComponentScan("ru.virgil.test_utils")
class BuyingOrderApiTest @Autowired constructor(
    private val requestUtil: RequestUtil,
    @Qualifier(BuyingOrderMocker.random)
    private val buyingOrderProvider: ObjectProvider<BuyingOrder>,
) {

    @Throws(Exception::class)
    @Test
    fun getAll(): Unit {
        val uriBuilder = URIBuilder().setPath("/buying_order")
            .addParameter(PAGE_PARAM, PAGE.toString())
            .addParameter(PAGE_SIZE_PARAM, PAGE_SIZE.toString())
        val buyingOrderDtoList = requestUtil.get(uriBuilder.toString())
            .receive(MutableList::class.java, BuyingOrderDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as List<BuyingOrderDto>
        Truth.assertThat(buyingOrderDtoList.stream().findAny().orElseThrow())
            .isInstanceOf(BuyingOrderDto::class.java)
    }

    @Test
    @Throws(Exception::class)
    fun get() {
        val buyingOrder = buyingOrderProvider.getObject()
        val randomBuyingOrderDto = requestUtil.get("/buying_order/${buyingOrder.uuid}")
            .receive(BuyingOrderDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BuyingOrderDto
        Truth.assertThat(randomBuyingOrderDto.description).isNotEmpty()
    }

    @Throws(Exception::class)
    @Test
    fun getTruckByOrder(): Unit {
        val buyingOrder = buyingOrderProvider.getObject()
        val uri = URIBuilder().setPathSegments("buying_order", buyingOrder.uuid.toString(), "truck")
            .addParameter(PAGE_PARAM, PAGE.toString())
            .addParameter(PAGE_SIZE_PARAM, PAGE_SIZE.toString())
            .toString()
        val truckDtoList = requestUtil.get(uri)
            .receive(MutableList::class.java, TruckDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as List<TruckDto>
        Truth.assertThat(truckDtoList.stream().findAny().orElseThrow()).isInstanceOf(TruckDto::class.java)
    }

    companion object {

        const val PAGE = 0
        const val PAGE_SIZE = 10
    }
}
