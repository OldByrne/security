package com.davidbyrne.security.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user")

//running the application will cause this class to create this table on the DB
public class User implements UserDetails { //UserDetails is an interface that needs to be implemented for Spring Security

    @Id
    @GeneratedValue //can clear this strategy as AUTO
    private int id;
    private String firstname;
    private String lastname;
    private String email; //also functioning as username
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role; //Role is an enum we made, can only have 2 values of either USER or ADMIN

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { //this method returns a users authorities based on the Role enum
        return List.of(new SimpleGrantedAuthority(role.name())); //SimpleGrantedAuthorities is from Spring Security
    }

    @Override
    public String getPassword() { //need to remove the above password variable for a second so you can get prompt to override this method from UserDetails
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
