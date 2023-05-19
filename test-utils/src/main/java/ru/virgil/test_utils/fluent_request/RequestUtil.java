package ru.virgil.test_utils.fluent_request;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class RequestUtil {

    private final Requester requester;
    private final ObjectMapper objectMapper;

    private BodyStepJson startJsonBuilding(RequestMethod requestMethod, String path) {
        RequestModel requestModel = new RequestModel();
        requestModel.setRequestMethod(requestMethod);
        requestModel.setUrl(path);
        return new BodyStepJson(requestModel, requester, objectMapper);
    }

    private BodyStepMultipartStart startMultipartBuilding(RequestMethod requestMethod, String path) {
        RequestModel requestModel = new RequestModel();
        requestModel.setRequestMethod(requestMethod);
        requestModel.setUrl(path);
        return new BodyStepMultipart(requestModel, requester, objectMapper);
    }

    public BodyStepJsonStart get(String path) {
        return startJsonBuilding(RequestMethod.GET, path);
    }

    public BodyStepJsonStart post(String path) {
        return startJsonBuilding(RequestMethod.POST, path);
    }

    public BodyStepJsonStart put(String path) {
        return startJsonBuilding(RequestMethod.PUT, path);
    }

    public BodyStepJsonStart delete(String path) {
        return startJsonBuilding(RequestMethod.DELETE, path);
    }

    public BodyStepMultipartStart postMultipart(String path) {
        return startMultipartBuilding(RequestMethod.POST_MULTIPART, path);
    }
}
