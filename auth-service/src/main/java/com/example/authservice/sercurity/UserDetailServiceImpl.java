package com.example.authservice.sercurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;
import java.util.List;

public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // giả lập tạo user. User phải được tạo từ db gọi lên và password phải được encode
        final List<AppUser> users = Arrays.asList(
                new AppUser(1, "tubean", encoder.encode("12345"), "USER"),
                new AppUser(2, "admin", encoder.encode("12345"), "ADMIN")
        );

        // check tu user goi ra tu database
        for (AppUser appUser : users) {
            if (appUser.getUserName().equals(username)) {
                // list role của người đó
                List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_" + appUser.getRole());
                // trả về danh sách user của người đó, class user được tạo ra sẵn bởi security nhằm trả về
                return new User(appUser.getUserName(), appUser.getPassword(), grantedAuthorities);
            }
        }

        // nếu user không tồn tại thì bắn ra lỗi
        throw new UsernameNotFoundException("Username: " + username + " not found");
    }
}
