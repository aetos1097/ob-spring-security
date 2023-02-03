package com.example.obspringsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration.
 * Clase para configurar la configuracion con sprinSecurity
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig  {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();//decodifca la password
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails adminUSer = User.withUsername("admin")
                .password(passwordEncoder().encode("2468"))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager( adminUSer);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/hola")
                .hasRole("ADMIN")
                .requestMatchers("/bootstrap")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();
        return httpSecurity.build();
    }

}
