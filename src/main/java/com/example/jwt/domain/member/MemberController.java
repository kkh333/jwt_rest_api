package com.example.jwt.domain.member;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {
    private final MemberService memberService;

    @Data
    public static class LoginRequest {
        @NotBlank
        private String username;
        @NotBlank
        private String password;
    }

    @PostMapping("/login")
    public Member login(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse resp) {

        //테스트용
//        resp.addHeader("Authentication", "JWT Token");

        String accessToken = memberService.genAccessToken(loginRequest.getUsername(), loginRequest.getPassword());

        resp.addHeader("Authentication", accessToken);

        return memberService.findByUsername(loginRequest.getUsername()).orElse(null);
    }
}