package com.usermanagement.server.service;

import com.usermanagement.server.domain.User;
import com.usermanagement.server.exception.EmailExistsException;
import com.usermanagement.server.exception.UserNotFoundException;
import com.usermanagement.server.exception.UsernameExistsException;

import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UsernameExistsException, UserNotFoundException, EmailExistsException;

    List<User> getAllUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

}
