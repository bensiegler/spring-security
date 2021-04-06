package org.springframework.security.web.authentication.twofa.stategies.sendfailure;

import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;

import javax.servlet.http.HttpServletRequest;

/**
 * Used to define a fallback behavior for when an exception is thrown while sending a code.
 *
 * @author Ben Siegler
 */
public interface TwoFactorAuthCodeSendFailureStrategy {

    void handleSendFailure(TwoFactorAuthCodeWrapper codeWrapper, HttpServletRequest request);
}
