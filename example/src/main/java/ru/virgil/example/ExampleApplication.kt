package ru.virgil.example

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity

@ConfigurationPropertiesScan
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true, securedEnabled = true)
@SpringBootApplication(
    scanBasePackages = ["ru.virgil.example", "ru.virgil.security", "ru.virgil.utils", "ru.virgil.test_utils"]
)
class ExampleApplication

private fun main(args: Array<String>) {
    SpringApplication.run(ExampleApplication::class.java, *args)
}
