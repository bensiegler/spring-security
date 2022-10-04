package org.springframework.security.web.authentication.twofa.stategies.sendattemp;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;

public class ConsolePrintTwoFactorAuthCodeSendStrategy implements TwoFactorAuthCodeSendStrategy {

	 public void sendCode(UserDetails userDetails, SignInAttempt codeWrapper) throws Exception {
		System.out.println(codeWrapper.getTwoFactorCode());
	}
}
