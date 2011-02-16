package com.example.authservice.sercurity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
// class đại diện cho thông tin của người dùng
public class UserCredentials {

    private String userName;

    private String password;


}
