package com.jwt.model;

import lombok.Data;
import lombok.Getter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
    private String roles; // USER, ADMIN

    public List<String> getRoleList() {

        if (0 < this.roles.length()) {
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }
}
