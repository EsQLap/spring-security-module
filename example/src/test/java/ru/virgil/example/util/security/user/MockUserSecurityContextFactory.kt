package ru.virgil.example.util.security.user

import org.springframework.security.core.context.SecurityContext
import org.springframework.security.test.context.support.WithSecurityContextFactory
import org.springframework.stereotype.Component
import ru.virgil.example.security.SecurityUserDetailsService
import ru.virgil.security.mock.MockSecurityContextFactory


@Component
class MockUserSecurityContextFactory(
    securityUserDetailsService: SecurityUserDetailsService,
) : WithSecurityContextFactory<WithMockFirebaseUser>, MockSecurityContextFactory(securityUserDetailsService) {

    override fun createSecurityContext(annotation: WithMockFirebaseUser): SecurityContext =
        createSecurityContext(annotation.firebaseUserId, annotation.firebaseAuthToken, *annotation.authorities)
}
