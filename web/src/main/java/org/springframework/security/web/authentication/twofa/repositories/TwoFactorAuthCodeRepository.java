package org.springframework.security.web.authentication.twofa.repositories;


import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;

public interface TwoFactorAuthCodeRepository {

    void insertCode(TwoFactorAuthCodeWrapper code);

    TwoFactorAuthCodeWrapper getCode(String sessionId);

    void removeCode(TwoFactorAuthCodeWrapper code);

    void removeCode(String sessionId);
}
