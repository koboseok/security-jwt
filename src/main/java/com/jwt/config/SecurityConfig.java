package com.jwt.config;

import com.jwt.config.jwt.JwtAuthenticationFilter;
import com.jwt.config.jwt.JwtAuthorizationFilter;
import com.jwt.filter.MyFilter1;
import com.jwt.filter.MyFilter3;
import com.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final CustomBCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // security 필터가 가장 먼저 동작한다.
        //http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다는 설정
                .and()
                // cors 정책 허용
                .addFilter(corsFilter) // @CrossOrigin(인증 X), 시큐리티 필터에 등록 (인증 O)
                .formLogin().disable() // form 로그인 안쓴다.
                .httpBasic().disable() // 기본적인 http 방식 안쓴다.
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // jwt 필터 등록
                // AuthenticationManager 를 파라미터로 던져주어야한다.
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)) // 인증이나 권한이 필요한 주소 요청 시 타는 필터
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

    }
}
