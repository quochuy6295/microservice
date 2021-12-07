package com.example.authservice.sercurity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {

    private Integer id;
    private String userName, password;

    private String role;

}
