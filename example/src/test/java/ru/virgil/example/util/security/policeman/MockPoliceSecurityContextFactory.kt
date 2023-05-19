package ru.virgil.example.util.security.policeman

import org.springframework.security.core.context.SecurityContext
import org.springframework.security.test.context.support.WithSecurityContextFactory
import org.springframework.stereotype.Component
import ru.virgil.example.security.SecurityUserDetailsService
import ru.virgil.security.mock.MockSecurityContextFactory

@Component
class MockPoliceSecurityContextFactory(
    securityUserDetailsService: SecurityUserDetailsService,
) : WithSecurityContextFactory<WithMockFirebasePoliceman>, MockSecurityContextFactory(securityUserDetailsService) {

    override fun createSecurityContext(annotation: WithMockFirebasePoliceman): SecurityContext =
        createSecurityContext(annotation.firebaseUserId, annotation.firebaseAuthToken, *annotation.authorities)
}
