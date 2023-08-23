package com.davidbyrne.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> { //the class and ID type

    Optional<User> findByEmail(String email); //Optional is a generic. findByEmail is the interpreted thing.

}
