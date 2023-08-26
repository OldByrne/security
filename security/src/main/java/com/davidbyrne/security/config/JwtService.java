package com.davidbyrne.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//can put this class in a service package really but following guidance so putting in config
@Service
public class JwtService {

    //constant variable that can only be accessed from within this class
    private static final String SECRET_KEY = "404d83f73f29e9aea034ceea39a231ac1a40f87339d878fd59a62930b4671619";


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); //subject is the email of the user
    }

    public <T> T extractClaim(String token, Function <Claims, T> claimsResolver){ //getting a single claim
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //returning a token using only the user details
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails); //using the below method to pass an empty map and the user details

    }

    //method overloading
    //method that helps us generate the token with extra claims as well as the user details
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){ //extra claims here would be like if you wanna add other authorities to the user
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) //to know when the token was made to check for outdated etc
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //24 hour valid token
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) //applying the signature sign in key we made in getSigInKey method
                .compact(); //generates and returns the token
    }

    //used to validate a token
    public boolean isTokenValid(String token, UserDetails userDetails){ //need token to check if it belongs to this user (UserDetails)
        final String username = extractUsername(token); //made this method in this class
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){ //this method will get all the claims from whatever token is passed in
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //setSignInKey is to do with the signature part of the JWT. ensuring that nothing has been changed
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


//need to manually add the following dependencies to pom:
// 		<dependency>
//			<groupId>io.jsonwebtoken</groupId>
//			<artifactId>jjwt-api</artifactId>
//			<version>0.11.5</version>
//		</dependency>
//		<dependency>
//			<groupId>io.jsonwebtoken</groupId>
//			<artifactId>jjwt-impl</artifactId>
//			<version>0.11.5</version>
//		</dependency>
// 		<dependency>
//			<groupId>io.jsonwebtoken</groupId>
//			<artifactId>jjwt-jackson</artifactId>
//			<version>0.11.5</version>
//		</dependency>
////
}
