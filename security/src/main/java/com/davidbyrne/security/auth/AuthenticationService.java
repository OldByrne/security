package com.davidbyrne.security.auth;

import com.davidbyrne.security.config.JwtService;
import com.davidbyrne.security.user.Role;
import com.davidbyrne.security.user.User;
import com.davidbyrne.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    //this allows us to create a user, save it to the database and return the generated token out of it
    public AuthenticationResponse register(RegisterRequest request) {
        //building the user object
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user); //no extra claims now, just needing the user
        return AuthenticationResponse.builder().token(jwtToken).build();

    }

    //this simply authenticates the user
    //the authentication manager does all the work here behind the scenes
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        //after this is only executed if the user is authenticated
        //then we just need to generate a token and send it back
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(); //this is just for this small project. need to learn about proper exception handling

        var jwtToken = jwtService.generateToken(user); //no extra claims now, just needing the user
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}