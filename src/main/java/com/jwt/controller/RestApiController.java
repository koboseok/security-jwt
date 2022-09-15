package com.jwt.controller;

import com.jwt.config.CustomBCryptPasswordEncoder;
import com.jwt.model.User;
import com.jwt.repository.UserRepository;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;


// @CrossOrigin 인증이 필요하지 않는 요청만 허용
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final CustomBCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {

        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {

        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) throws Exception {


        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        System.out.println(user);
        userRepository.save(user);

        return "회원가입 완료 !!";

    }

    // user, manager, admin 권한만 접근 가능
    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }

    // manager, admin 권한
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }
    // admin 권한
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }


}
