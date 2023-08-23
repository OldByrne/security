package com.davidbyrne.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor //used if we need to make final variables for dependency injection
public class JwtConfigurationFilter extends OncePerRequestFilter { //OncePerRequestFilter used so it fires every time there is a filter request

    private final JwtService jwtService; //injection

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, //should read more into this method
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        //now to check the JWT token
        final String authHeader = request.getHeader("Authorization"); //getting a header from request which has token info on it
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){ //validation check, if it's null or not starting with Bearer
            filterChain.doFilter(request, response); //then move on to the next request/response (not too clear on this meaning)
        }
        jwt = authHeader.substring(7); //because we get the token after "Bearer " (7 chars)
        //so far we have gotten the JWT token (jwt) being sent from the user. next is to use this token to check if this user is in the DB
        //first though we need to execute a JwtService to extract the username. keep referring to the diagram to see how this is flowing.
        userEmail = jwtService.extractUsername(jwt);
    }

}
