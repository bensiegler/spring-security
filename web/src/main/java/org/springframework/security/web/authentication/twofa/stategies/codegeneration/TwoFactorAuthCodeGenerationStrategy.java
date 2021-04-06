package org.springframework.security.web.authentication.twofa.stategies.codegeneration;

public interface TwoFactorAuthCodeGenerationStrategy {
    String generateCode();
}
