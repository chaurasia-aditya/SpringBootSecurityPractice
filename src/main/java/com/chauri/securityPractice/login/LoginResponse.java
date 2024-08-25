package com.chauri.securityPractice.login;

import java.util.List;

public class LoginResponse {
    private String userName;
    private List<String> roles;
    private String jwtToken;

    public LoginResponse(String userName, List<String> roles, String jwtToken) {
        this.userName = userName;
        this.roles = roles;
        this.jwtToken = jwtToken;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
