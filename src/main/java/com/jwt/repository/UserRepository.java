package com.jwt.repository;

import com.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

   User findByUsername(String username);

}
