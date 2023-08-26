package com.davidbyrne.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor //used if we need to make final variables for dependency injection
//OncePerRequestFilter used so it fires only once when there is a filter request
//helps avoid multiple security filters being run on a single request
//this class will be doing the work on the tokens using the jwtservice methods
public class JwtConfigurationFilter extends OncePerRequestFilter {

    private final JwtService jwtService; //injection
    private final UserDetailsService userDetailsService; //this is an already existing Spring interface that we are using

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
            filterChain.doFilter(request, response); //move on to the next request/response if passes
        }
        jwt = authHeader.substring(7); //because we get the token after "Bearer " (7 chars)

        //so far we have gotten the JWT token (jwt) being sent from the user. next is to use this token to check if this user is in the DB
        //first though we need to execute a JwtService to extract the username. keep referring to the diagram to see how this is flowing.
        userEmail = jwtService.extractUsername(jwt);
        //checking not null and also that the user is not already authenticated
        //SecurityContextHolder.getContext().getAuthentication() == null just means user is not yet authenticated
        //next at 1:24:40 is recapped quickly
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //checking if the user is actually in the database
            //now to check if the token is still valid
            if(jwtService.isTokenValid(jwt, userDetails)){ //if valid
                //this is getting the username authentication token
                //if it is valid we create an object of UsernamePasswordAuthenticationToken
                //pass in user details, credentials and authorities into it
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                //then enforce the authToken with the details of the request (not 100% on this)
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //then update the authentication token
                //this is basically saying to the SecurityContextHolder that the token is good and its details
                //the SecurityContextHolder is the last stage before accessing the DispatcherServlet. CHECK THE DIAGRAM
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response); //after the above "if", passing on to the next filter to be executed
    }

}
