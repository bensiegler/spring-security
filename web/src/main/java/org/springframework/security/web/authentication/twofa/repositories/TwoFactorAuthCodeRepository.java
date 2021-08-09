package org.springframework.security.web.authentication.twofa.repositories;


import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;

public interface TwoFactorAuthCodeRepository {

    void insertCode(SignInAttempt code);

    SignInAttempt getCode(String sessionId);

    void removeCode(SignInAttempt code);

    void removeCode(String sessionId);
}
