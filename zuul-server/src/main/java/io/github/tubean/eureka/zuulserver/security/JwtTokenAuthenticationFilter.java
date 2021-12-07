package io.github.tubean.eureka.zuulserver.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;

    public JwtTokenAuthenticationFilter(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // 1. Lấy tiêu đề xác thực. Các mã thông báo phải được chuyển trong tiêu đề xác thực
        String header = request.getHeader(jwtConfig.getHeader());

        // 2 Kiểm tra header và kiểm tra tiền tố ban đầu
        if (header == null || !header.startsWith(jwtConfig.getPrefix())){
            chain.doFilter(request, response);  // Nếu không hợp lệ, di chuyển đến filer tiếp tục
            return;
        }

        // nếu không có mã nào được thông báo thì người dung không tồn tại
        // Nếu có, có thể người dùng yêu cầu mã công khai và đang chờ đợi path cho token

        // 3. Gọi ra token
        String token = header.replace(jwtConfig.getHeader(), "");

        // các ngoại lệ được đưa ra với trường hợp các lỗi xảy ra đối với token
        try {
            //4. validate đối với token
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtConfig.getSecret().getBytes())
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            if (username != null) {
                List<String> authorities = (List<String>) claims.get("authorities");

                // 5. Create auth object
                // UsernamePasswordAuthenticationToken là 1 đối tượng tích hợp đại diện cho người dùng đang tích hợp trong spring đang login
                // Nó cần 1 danh sách các authorities trong đó GrantedAuthority có đại diện là SimpleGrantedAuthority
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            }
        } catch (Exception e) {
            // trong trường hợp lỗi phải xử lý lỗi
            SecurityContextHolder.clearContext();
        }

        // chuyển đến filter tiếp theo trong chuỗi bộ lọc
        chain.doFilter(request, response);
    }
}
