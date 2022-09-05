package com.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.config.auth.PrincipalDetails;
import com.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 한다.

// /login 으로 요청이 들오면 UsernamePasswordAuthenticationFilter 가 낚아채서  attemptAuthentication 함수가 자동으로 실행된다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 시큐리티에 .formLogin().disable() 설정을 해놓았음으로 이 필터는 동작하지 않는다.
    // 어떻게하면 다시 작동시킬수 있냐 ?
    // JwtAuthenticationFilter 필터를 다시 시큐리티 필터에 등록을 하면 된다.
    // addFilter(new JwtAuthenticationFilter(authenticationManager()));

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. username, password 받아서
        // 2. 정상인지 아닌지, authenticationManager로 로그인 시도를 하면!!
        //    PrincipalDetailsService가 실행되고 이 서비스 안에 있는 loadUserByUsername이 자동으로 실행된다.
        // 3. PrincipalDetails를 세션에 담고 -> 굳이 담는 이유는 시큐리티에서 권한관리를 해주야하기 떄문에 ex) user, admin
        // 4. JWT 토큰을 만들어서 응답해주면된다.
        try {
           /*
           BufferedReader br = request.getReader();
            String input = null;
            while ((input = br.readLine()) != null) {
                System.out.println(input);
            }
            */

            // json pasing
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            // authenticationManager에 토큰을 넣어서 던진다.
            // authentication에 내 로그인 정보가 담긴다.
            // 로그인 시도가 정상적으로 되면  authentication 객체가 만들어진다.  authenticationManager 에 의해서..
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);


            // object return 이기에 다운캐스팅
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername()); // 로그인 정상적으로 되었다는 뜻

            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 된다.
            // 리턴의 이유는 권한관리를 security가 대신 해주기 때문에 편하려고 하는거임
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다. 단지 권한처리 때문에 session 넣어준다.

            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication() 실행 후 인증이 정상적으로 되었으면 successfulAuthentication() 함수가 실행된다.
    // 이 함수에서 JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료 되었다는 뜻임.");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니고 Hash 암호방식이다.
        // HMAC256 특징은 서버만 알고있는 secret을 가지고 있어야한다.
        String jwtToken = JWT.create()
                .withSubject("cos-token") // 토큰 이름
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // 만료시간 (10분) 토큰 만료시간은 길면 별로 .. ?
                // withClaim => 비공개 클레임 넣고싶은 값 넣는다.
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC256("cos")); // 내 서버만 아는 고유값

        // Bearer(문자열) 뒤에 한칸 띄워야함.
        response.addHeader("Authorization","Bearer " + jwtToken);
    }
}
