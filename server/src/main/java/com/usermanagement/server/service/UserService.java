package com.usermanagement.server.service;

import com.usermanagement.server.domain.User;
import com.usermanagement.server.exception.EmailExistsException;
import com.usermanagement.server.exception.EmailNotFoundException;
import com.usermanagement.server.exception.UserNotFoundException;
import com.usermanagement.server.exception.UsernameExistsException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UsernameExistsException, UserNotFoundException, EmailExistsException, MessagingException;

    List<User> getAllUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UsernameExistsException, UserNotFoundException, EmailExistsException, IOException;

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UsernameExistsException, UserNotFoundException, EmailExistsException, IOException;

    void deleteUser(Long id);

    void resetPassword(String email) throws EmailNotFoundException, MessagingException;

    User updateProfileImage(String username, MultipartFile profileImage) throws UsernameExistsException, UserNotFoundException, EmailExistsException, IOException;

}
