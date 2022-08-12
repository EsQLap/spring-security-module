package ru.virgil.example.image;

import org.springframework.stereotype.Service;
import ru.virgil.example.user.UserDetails;
import ru.virgil.utils.FakerUtils;
import ru.virgil.utils.image.ImageService;

import javax.annotation.PreDestroy;
import java.io.IOException;

@Service
public class ImageMockService extends ru.virgil.utils.image.ImageMockService<UserDetails, PrivateImageFile> {

    public ImageMockService(ImageService<UserDetails, PrivateImageFile> imageService, FakerUtils fakerUtils) {
        super(imageService, fakerUtils);
    }

    // todo: удалит даже нужные картинки?
    @PreDestroy
    public void preDestroy() throws IOException {
        imageService.cleanFolders();
    }
}
