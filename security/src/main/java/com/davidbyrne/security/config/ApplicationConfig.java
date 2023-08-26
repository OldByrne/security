package com.davidbyrne.security.config;

import com.davidbyrne.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//this will hold all the app configs e.g. Beans
//using @Configuration will make spring pick up this class on start up and implement/inject all beans declared here in the class
@Configuration
@RequiredArgsConstructor //commonly used if we inject something into this class, this is needed for what is being injected
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean //this indicates that the following method represents a bean. bean is always public
    public UserDetailsService userDetailsService(){ //this is part of Spring security
        return new UserDetailsService() { //hover over the name here to optionally replace this with lambda expression
            //here we are implementing the loadUserByUsername method which is used in JwtConfigurationFilter
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                //need to have the throw here in case there is no user found. also using lambda expression (->)
                return userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found.") );
            }
        };
    }

    @Bean
    //data access object responsible for fetching user details and encode passwords etc
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService()); //setting which UserDetailsService to use. in other projects, could have multiple implementations of UserDetails
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    //responsible for managing authentication using username and password
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
