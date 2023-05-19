package ru.virgil.test_utils.fluent_request;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import ru.virgil.test_utils.TestUtils;

import java.util.Optional;

@RequiredArgsConstructor
@Component
public class Requester {

    private final MockMvc mockMvc;
    private final TestUtils testUtils;
    private final ObjectMapper jackson;

    private MockHttpServletRequestBuilder getHttpBuilder(RequestMethod requestMethod, String url) {
        return switch (requestMethod) {
            case GET -> MockMvcRequestBuilders.get(url);
            case POST -> MockMvcRequestBuilders.post(url);
            case PUT -> MockMvcRequestBuilders.put(url);
            case DELETE -> MockMvcRequestBuilders.delete(url);
            case POST_MULTIPART -> MockMvcRequestBuilders.multipart(url);
        };
    }

    private void addBody(MockHttpServletRequestBuilder builder, Object objectBody) throws JsonProcessingException {
        String jsonBody = jackson.writeValueAsString(objectBody);
        builder.content(jsonBody)
                .contentType(MediaType.APPLICATION_JSON);
    }

    private void addFile(MockMultipartHttpServletRequestBuilder builder, MockMultipartFile mockMultipartFile) {
        builder.file(mockMultipartFile);
    }

    protected MvcResult makeRequest(RequestModel requestModel) throws Exception {
        MockHttpServletRequestBuilder builder = getHttpBuilder(requestModel.getRequestMethod(), requestModel.getUrl());
        if (Optional.ofNullable(requestModel.getRequestBody()).isPresent()) {
            addBody(builder, requestModel.getRequestBody());
        } else if (Optional.ofNullable(requestModel.getMockMultipartFile()).isPresent()) {
            addFile((MockMultipartHttpServletRequestBuilder) builder, requestModel.getMockMultipartFile());
        }
        return mockMvc.perform(builder)
                .andExpectAll(requestModel.getResultMatchers())
                .andDo(testUtils::printResponse)
                .andReturn();
    }
}
