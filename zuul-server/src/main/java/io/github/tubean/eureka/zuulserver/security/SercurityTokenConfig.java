package io.github.tubean.eureka.zuulserver.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

public class SercurityTokenConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()// chống kỹ thuật bằng cách giả mạo chủ thê
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // đảm bảo rằng chúng ta sử dụng staless session, session khong được sử dụng để lưu thông tin user
        .and()
                // xử lý nỗ lực ủy quyền
        .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // thêm bộ lọc để xác thực mã thông báo với mọi yêu cầu (bộ lọc này là 1 class) (lọc token gửi xuống)
        .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                // phần quyền đối với từng tác vụ
        .authorizeRequests()
                // cho phép tất cả mọi người có thể truy cập vào auth service
        .antMatchers(HttpMethod.POST, jwtConfig.getUrl()).permitAll()
                // phải là quản trị viên khi muốn truy cập vào quản trị
        .antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
                // tất cả các yêu cầu phải được đăng nhập
        .anyRequest().authenticated();
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }
}
