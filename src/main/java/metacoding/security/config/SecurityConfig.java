package metacoding.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
public class SecurityConfig {

    // 해당 메서드의 리턴되는 오브젝트를 IOC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());

        http.authorizeHttpRequests(authorize -> {
            authorize
                    .requestMatchers("/user/**").authenticated()
                    .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                    .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                    .anyRequest().permitAll();
        });

        http.formLogin(form -> {
            form.
                    loginPage("/loginForm")
                    .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행
                    .defaultSuccessUrl("/");
        });

        return http.build();
    }
}
