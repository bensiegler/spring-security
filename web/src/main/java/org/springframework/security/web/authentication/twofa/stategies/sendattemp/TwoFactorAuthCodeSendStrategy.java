package org.springframework.security.web.authentication.twofa.stategies.sendattemp;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;

/**
 *  An interface used to define a strategy for sending two factor authentication codes.
 *  <p>
 *  Would commonly define a way of sending an email or a text message.
 *
 * @author Ben Siegler
 */
public interface TwoFactorAuthCodeSendStrategy {

    void sendCode(UserDetails userDetails, SignInAttempt codeWrapper) throws Exception;

}
