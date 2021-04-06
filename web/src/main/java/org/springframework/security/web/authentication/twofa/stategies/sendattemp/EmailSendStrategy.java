package org.springframework.security.web.authentication.twofa.stategies.sendattemp;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;

import javax.mail.Message;
import javax.mail.MessagingException;

public abstract class EmailSendStrategy implements TwoFactorAuthCodeSendStrategy {

    @Override
    public void sendCode(UserDetails userDetails, TwoFactorAuthCodeWrapper code) throws MessagingException {
        Message message = generateEmailContent(code.getTwoFactorCode(), userDetails.getTwoFactorAuthSendLocation());
        sendEmail(message);
    }

    public abstract Message generateEmailContent(String code, String emailAddress) throws MessagingException;

	public abstract void sendEmail(Message message) throws MessagingException;
}
