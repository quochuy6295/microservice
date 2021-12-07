package com.example.authservice.sercurity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

// check user name password và trả lại 1 token
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // sử dụng lớp authentication manager để xác thực thông tin người dùng
    private AuthenticationManager authenticationManager;

    private final JwtConfig jwtConfig;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfig jwtConfig) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;

        // By default, UsernamePasswordAuthenticationFilter listens to "/login" path.
        // In our case, we use "/auth". So, we need to override the defaults.
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUrl(), "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            // 1. Nhận thông tin xác thực từ yêu cầu
            UserCredentials credentials = new ObjectMapper().readValue(request.getInputStream(), UserCredentials.class);

            // 2. Tạo đối tượng xác thực, cái mà sẽ được xác thực bởi manager
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    credentials.getPassword(), credentials.getUserName(), Collections.emptyList()
            );

            // 3. Trình quản lý xác thực người dùng và sử dụng phương thức UserDetailServiceImpl:: loadUserByUsername() để tải người dùng
            return authenticationManager.authenticate(authToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Sau khi success authentication, sẽ tạo nên token
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            Authentication auth) throws IOException, ServletException {

        Long now = System.currentTimeMillis();
        String token = Jwts.builder()
                .setSubject(auth.getName())
                // chuyển đổi list thành string, điều này quan trọng vì nó ảnh hưởng đến việc gửi lại token lại gateway
                .claim("authorities", auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + jwtConfig.getExpiration() * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
                .compact();
        // add token to header, header cũ + token sau khi xác thực
        response.addHeader(jwtConfig.getHeader(), jwtConfig.getPrefix() + token);
    }
}
