package com.example.springoauthdemo;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class MySuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    public MySuccessHandler(String defaultUrl) {
        setDefaultTargetUrl(defaultUrl);
    }
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
/*        HttpSession session = request.getSession();
        String redirectUrl = (String) session.getAttribute("url_prior_login");
        session.removeAttribute("url_prior_login");
        session.setAttribute("url_prior_login", "http://localhost:8082/ui/secure");
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
   */   getRedirectStrategy().sendRedirect(request , response, getDefaultTargetUrl());
        }
    }

