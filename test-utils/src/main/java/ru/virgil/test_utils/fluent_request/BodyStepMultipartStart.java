package ru.virgil.test_utils.fluent_request;

import org.springframework.mock.web.MockMultipartFile;

public interface BodyStepMultipartStart {

    BodyStepMultipart file(MockMultipartFile mockMultipartFile) throws Exception;
}
