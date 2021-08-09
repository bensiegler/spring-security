package org.springframework.security.web.authentication.twofa.stategies.sendfailure;

import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;

import javax.servlet.http.HttpServletRequest;

public class NullSendFailureStrategy implements TwoFactorAuthCodeSendFailureStrategy {
	@Override
	public void handleSendFailure(SignInAttempt codeWrapper, HttpServletRequest request) {

	}
}
