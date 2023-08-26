package com.davidbyrne.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//when the app starts, spring security looks for a bean of type SecurityFilterChain
//SecurityFilterChain is responsible for configuring all the HTTP security of the application
public class SecurityConfiguration {

    private final JwtConfigurationFilter jwtAuthFilter; //misnamed from tut (JwtAuthenticationFilter)
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http .csrf(csrf -> csrf.disable()) //disabling this validation that is depreciated
                .authorizeHttpRequests( //whitelisting
                        auth -> auth
                                .requestMatchers("/api/v1/auth/**").permitAll() //permit all access to this
                                .anyRequest().authenticated() //any other request should be authenticated
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //making the log in session stateless so every request is authenticated
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
