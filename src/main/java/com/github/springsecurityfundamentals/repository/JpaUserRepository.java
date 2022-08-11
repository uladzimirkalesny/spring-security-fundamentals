package com.github.springsecurityfundamentals.repository;

import com.github.springsecurityfundamentals.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface JpaUserRepository extends JpaRepository<User, Long> {

    @EntityGraph(attributePaths = {"authorities"})
    @Query("SELECT u FROM User u WHERE u.username = :username")
    Optional<User> findUserWithAuthoritiesByUsername(String username);

}
