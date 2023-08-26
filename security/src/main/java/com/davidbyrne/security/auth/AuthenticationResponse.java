package com.davidbyrne.security.auth;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    //this token is what is sent back to the user
    private String token;


}
