package org.springframework.security.web.authentication.twofa.stategies.sendattemp;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;

import javax.mail.MessagingException;

/**
 *  A class used to define a strategy for sending two factor authentication codes.
 *  <p>
 *  Would commonly lay out a way of sending an email or a text message.
 *
 * @author Ben Siegler
 */
public interface TwoFactorAuthCodeSendStrategy {

    void sendCode(UserDetails userDetails, TwoFactorAuthCodeWrapper codeWrapper) throws MessagingException;

}
