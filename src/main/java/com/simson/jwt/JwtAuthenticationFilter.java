package com.simson.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.simson.jwt.config.auth.PrincipalDetails;
import com.simson.jwt.model.User;
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

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면 (post) 이 필터가 동작한다.
// formLogin을 disable하면 동작안함
//
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중 ");

        // 1. username, password 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //이게 실행될때 PrincipalDetailsService의 loadUserByUsername() 함수가 실행 된 후 정상이면 authentication이 리턴됨.
            //DB에 있는 username과 password가 일치한다는 뜻.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);
            // 로그인이 되었다는 뜻.

            PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
            System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());// 로그인 정상적으로 되었다는 뜻.

            // 리턴 될 때 authentication 객체가 session영역에 저장을 해야하고 그 방법이 return해주면 됨.
            // 권한 관리를 시큐리티가 대신 해주기 때문에 편하려고 하기 떄문이다.
            // 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 SESSION에 넣어 줌

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

       return null;
    }

    // attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행 된다.
    // JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication실행 됨 : 인증이 완료되었다는 뜻 ");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
