package org.springframework.security.web.authentication.ui;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.TwoFactorPreference;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.CodeSigner;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class DefaultTwoFactorChoiceGeneratingFilter extends GenericFilterBean {

	private String choiceUrl;

	private String loginPageUrl;

	private String failureUrl;

	private TwoFactorAuthCodeService codeService;

	private UserDetailsService userDetailsService;

	public DefaultTwoFactorChoiceGeneratingFilter(String choiceUrl, String loginPageUrl, String failureUrl, TwoFactorAuthCodeService codeService, UserDetailsService userDetailsService) {
		this.choiceUrl = choiceUrl;
		this.loginPageUrl = loginPageUrl;
		this.failureUrl = failureUrl;
		this.codeService = codeService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException{
		boolean loginError = isErrorPage(request);
		if (isChoiceUrl(request) || loginError) {
			UserDetails details;
			try {
				String username = codeService.getUsernameFromSessionId(request.getRequestedSessionId());
				details = userDetailsService.loadUserByUsername(username);
			}catch (Exception e) {
				response.sendRedirect(loginPageUrl);
				return;
			}
			String loginPageHtml = generateTwoFactorChoicePage(request, details, loginError);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginPageHtml);
			return;
		}
		chain.doFilter(request, response);
	}

	private boolean isErrorPage(HttpServletRequest request) {
		return matches(request, this.failureUrl);
	}

	private boolean isChoiceUrl(HttpServletRequest request) {
		return matches(request, choiceUrl);
	}

	private boolean matches(HttpServletRequest request, String url) {
		if (!"GET".equals(request.getMethod()) || url == null) {
			return false;
		}
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');
		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}
		if (request.getQueryString() != null) {
			uri += "?" + request.getQueryString();
		}
		if ("".equals(request.getContextPath())) {
			return uri.equals(url);
		}
		return uri.equals(request.getContextPath() + url);
	}

	public String generateTwoFactorChoicePage(HttpServletRequest request, UserDetails userDetails, boolean isError) {
		String contextPath = request.getContextPath();
		HashMap<Integer, TwoFactorPreference> preferences = userDetails.getTwoFactorAuthPreferences();
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>\n");
		sb.append("<html lang=\"en\">\n");
		sb.append("  <head>\n");
		sb.append("    <meta charset=\"utf-8\">\n");
		sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		sb.append("    <meta name=\"description\" content=\"\">\n");
		sb.append("    <meta name=\"author\" content=\"\">\n");
		sb.append("    <title>Please sign in</title>\n");
		sb.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n");
		sb.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		sb.append("  </head>\n");
		sb.append("  <body>\n");
		sb.append("     <div class=\"container\">\n");
		for(Integer i: preferences.keySet()) {
			TwoFactorPreference p = preferences.get(i);
			String name;
			if(p.isKey()) {
				name = "Use Authenticator App";
			}else{
				name = "Send code to " + p.getData();
			}

			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath
					+ this.choiceUrl + "/" + i + "\">\n");
			sb.append("        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">" + name + "</button>\n");
			sb.append("      </form>\n");
		}
		sb.append("		</div>\n");
		sb.append("	 </body>\n");
		sb.append("</html>");

		return sb.toString();
	}

}
