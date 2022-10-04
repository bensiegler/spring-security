package org.springframework.security.web.authentication.twofa.services;

import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;
import org.springframework.security.web.authentication.twofa.repositories.TwoFactorAuthCodeRepository;
import org.springframework.security.web.authentication.twofa.stategies.codegeneration.TwoFactorAuthCodeGenerationStrategy;

import javax.servlet.http.HttpServletRequest;

public interface TwoFactorAuthCodeService {

    String generateCode(HttpServletRequest request, String username);

    SignInAttempt getCode(String sessionId);

	SignInAttempt saveAttempt(HttpServletRequest request, String username, String twoFactorCode);

    void cleanUp(String sessionId);

    boolean isPasswordVerified(String sessionId);

    void setCodeRepository(TwoFactorAuthCodeRepository codeRepository);

    void setCodeGenerationStrategy(TwoFactorAuthCodeGenerationStrategy generationStrategy);

    void setExpirationTime(long expirationTime);

    String getUsernameFromSessionId(String sessionId);

    boolean isCodeExpired(SignInAttempt signInAttempt);
}
