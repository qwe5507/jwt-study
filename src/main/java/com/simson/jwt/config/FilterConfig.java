package com.simson.jwt.config;

import com.simson.jwt.filter.MyFilter1;
import com.simson.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*"); //모든요청에 실행
        bean.setOrder(0); // 낮은 번호가 필터 중에서 가장먼저 실행 된다.
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*"); //모든요청에 실행
        bean.setOrder(1); // 낮은 번호가 필터 중에서 가장먼저 실행 된다.
        return bean;
    }

}
