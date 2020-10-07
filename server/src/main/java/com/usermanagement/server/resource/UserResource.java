package com.usermanagement.server.resource;

import com.usermanagement.server.exception.ExceptionHandlerAdvice;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = {"/", "/user"})
public class UserResource extends ExceptionHandlerAdvice {

    @GetMapping("/home")
    public String showUser() {
        return "Application Works";
    }
}
