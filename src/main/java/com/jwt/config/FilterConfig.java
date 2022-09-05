package com.jwt.config;


import com.jwt.filter.MyFilter1;
import com.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration // ioc 등록
public class FilterConfig {

    @Bean
    FilterRegistrationBean<MyFilter1> filter1(){

        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*"); // all request
        bean.setOrder(1); // 낮은 번호가 필터중에서 가장 먼저 실행된다.
        return bean;
    }

    @Bean
    FilterRegistrationBean<MyFilter2> filter2(){

        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*"); // all request
        bean.setOrder(0); // 낮은 번호가 필터중에서 가장 먼저 실행된다.
        return bean;
    }

}
