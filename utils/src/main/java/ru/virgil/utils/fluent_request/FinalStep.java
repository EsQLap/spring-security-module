package ru.virgil.utils.fluent_request;

import org.springframework.test.web.servlet.ResultMatcher;

public interface FinalStep<T> {

    T expect(ResultMatcher... expectMatchers) throws Exception;
}
