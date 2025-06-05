package com.example.test.controller;

import com.example.test.domain.User;
import com.example.test.dto.UserInfoResponseDto;
import com.example.test.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;

    @GetMapping
    public List<UserInfoResponseDto> getUsers() {
        List<User> users = userRepository.findAll();

        return users.stream().map(UserInfoResponseDto::new).toList();
    }
}
