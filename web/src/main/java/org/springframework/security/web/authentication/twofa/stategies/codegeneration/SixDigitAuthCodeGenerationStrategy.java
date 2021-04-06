package org.springframework.security.web.authentication.twofa.stategies.codegeneration;

public class SixDigitAuthCodeGenerationStrategy implements TwoFactorAuthCodeGenerationStrategy {

    public String generateCode() {
        StringBuilder code = new StringBuilder();

        for(int i = 0; i < 6; i++) {
            int newDigit = (int) (Math.random() * 10);
            code.append(newDigit);
        }

        return code.toString();
    }
}
