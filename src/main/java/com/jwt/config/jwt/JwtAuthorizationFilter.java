package com.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.config.auth.PrincipalDetails;
import com.jwt.model.User;
import com.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter를 가지고 있는데 그 필터 중 BasicAuthenticationFilter 라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;

    }
    /*
        1.사용자가 http request.

        2-1.로그인 요청이라면 (UsernamePasswordAuthenticationFilter를 상속한) AuthenticationFilter가
        attemptAuthentication()를 실행되고 그 후 successfulAuthentication()을 실행된다.
        해당 과정에서 토큰을 만들고 해당 토큰을 response 헤더에 담아준다.
        2-2.이미 토큰을 발급받아 같이 요청한 상태라면, (UsernamePasswordAuthenticationFilter를상속한) AuthenticationFilter에서 아무런 동작없이 바로 인가처리로 이어진다.
        (BasicAuthenticationFilter를 상속한 AuthorizationFilter)

        3.BasicAuthenticationFilter를 상속한 AuthorizationFilter에서 받은 토큰을 parse하여 해당 Id가 db에
        저장되어 있는지 확인한다.그후 존재한다면,해당 유저정보와 해당 유저의 권한이 담긴 토큰을
        SecurityContextHolder를 사용하여 세션값에 저장한다.(권한 부여)
        Ex) SecurityContextHolder.getContext().setAuthentication(authentication);
     */

    // 인증이나 권한이 필요한 주소요청이 있을때 해당 필터를 타게된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소가 요청 됨.");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        System.out.println("jwtHeader = " + jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }
        // jwt 토큰을 검증해서 정삭적인 사용자인지 확인
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
        System.out.println("jwtToken = " + jwtToken);
        String username = JWT.require(Algorithm.HMAC256(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됨
        if (username != null) {

            System.out.println("username  = " + username);
            User user = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(user);
            // jwt 토큰 서명을 통해서 서명이 정상이면
            // 강제로 Authentication 객체 만들기
            // => 왜 강제로 만들 수 있냐 서명이 정상적으로 진행이 되어 검증이 됐기 때문에
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 시큐리티를 저장할 수 있는 세션 공간
            // 강제로 시큐리트의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);

    }
}
