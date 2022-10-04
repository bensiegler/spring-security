package org.springframework.security.web.authentication.twofa.stategies.codegeneration;

//Implementation code generation strategy that generates a six-digit code
public class TwoFactorAuthCodeGenerationStrategyImpl implements TwoFactorAuthCodeGenerationStrategy {

    public String generateCode() {
        StringBuilder code = new StringBuilder();

        for(int i = 0; i < 6; i++) {
            int newDigit = (int) (Math.random() * 10);
            code.append(newDigit);
        }

        return code.toString();
    }
}
