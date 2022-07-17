package ru.virgil.example.image;

import org.springframework.stereotype.Repository;
import ru.virgil.example.user.UserDetails;
import ru.virgil.utils.image.IPrivateImageRepository;

@Repository
public interface PrivateImageRepository extends IPrivateImageRepository<UserDetails, PrivateImageFile> {

}
