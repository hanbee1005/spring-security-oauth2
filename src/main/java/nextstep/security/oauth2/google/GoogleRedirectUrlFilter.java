package nextstep.security.oauth2.google;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

public class GoogleRedirectUrlFilter extends GenericFilterBean {
    private static final String AUTHORIZATION_REQUEST_URL = "/oauth2/authorization/google";
    private static final String GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth?";
    public static final String REDIRECT_URL = "http://localhost:8080/login/oauth2/code/google";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (!request.getMethod().equals("GET")
                || !request.getRequestURI().equals(AUTHORIZATION_REQUEST_URL)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        String queryParams = UriComponentsBuilder.newInstance()
                .queryParam("client_id", "88951150265-q7aq5urrim4rrtqo62hc96o6r5v7r34c.apps.googleusercontent.com")
                .queryParam("response_type", "code")
                .queryParam("scope", "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email")
                .queryParam("redirect_uri", REDIRECT_URL)
                .build()
                .toUri()
                .getQuery();

        response.sendRedirect(GOOGLE_AUTHORIZATION_URL + queryParams);
    }
}
