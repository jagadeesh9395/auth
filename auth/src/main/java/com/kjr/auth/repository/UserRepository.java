package com.kjr.auth.repository;

import com.kjr.auth.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    @Query("{'$or':[ {'username': ?0}, {'email': ?1} ]}")
    Optional<User> findByUsernameOrEmail(String username, String email);
}
