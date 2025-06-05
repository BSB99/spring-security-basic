package com.example.test.dto;

import com.example.test.domain.User;
import lombok.Data;

@Data
public class UserInfoResponseDto {
    private Long id;
    private String username;
    private String password;

    public UserInfoResponseDto(User user) {
        this.id = user.getId();
        this.username = user.getUserName();
        this.password = user.getPassword();
    }
}
