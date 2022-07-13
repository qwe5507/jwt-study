package com.simson.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면 (post) 이 필터가 동작한다.
// formLogin을 disable하면 동작안함
//
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login요청을 하면 로그인 시도를 위해서 실행되는 함수
    // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
    // 인증 요청시에 실행되는 함수 => /login
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

                //깃헙 authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
                // loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
                // UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
                // UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
                // Authentication 객체를 만들어서 필터체인으로 리턴해준다.

                // Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
                // Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
                // 결론은 인증 프로바이더에게 알려줄 필요가 없음.
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

        PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();

        // RSA방식은 아니고 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
