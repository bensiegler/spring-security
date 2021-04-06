package org.springframework.security.web.authentication.twofa.services;


import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;
import org.springframework.security.web.authentication.twofa.repositories.TwoFactorAuthCodeRepository;
import org.springframework.security.web.authentication.twofa.stategies.codegeneration.TwoFactorAuthCodeGenerationStrategy;

import javax.servlet.http.HttpServletRequest;

public interface TwoFactorAuthCodeService {

    TwoFactorAuthCodeWrapper generateCode(HttpServletRequest request, String username);

    TwoFactorAuthCodeWrapper validateCode(String codeToCheck, String sessionId) throws BadCredentialsException;

    TwoFactorAuthCodeWrapper getCode(String sessionId);

    void cleanUp(String sessionId);

    boolean isAwaitingCode(String sessionId);

    void setCodeRepository(TwoFactorAuthCodeRepository codeRepository);

    void setCodeGenerationStrategy(TwoFactorAuthCodeGenerationStrategy generationStrategy);

    void setExpirationTime(long expirationTime);


}
