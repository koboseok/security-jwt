package com.jwt.config.auth;

import com.jwt.model.User;
import com.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


// http://localhost:8080/login => 여기서 동작을 안한다. 404
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println("PrincipalUserDetailsSerice의 loadUserByUsername()");
        User user = userRepository.findByUsername(username);
        return new PrincipalDetails(user);
    }
}
