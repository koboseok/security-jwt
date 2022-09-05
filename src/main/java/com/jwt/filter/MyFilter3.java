package com.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 시큐리티가 동작하기전에 걸러내야한다.

        // 다운 캐스팅
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰 : cos
        // => id,pw 가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        // 요청할 때 마다 header에 Authorization에 value 값으로 토큰을 가지고 온다.
        // 이때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다. ( RSA, HS256 )
        if (req.getMethod().equals("POST")) {
            System.out.println("request POST !");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터 3");

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }

        }

    }
}
