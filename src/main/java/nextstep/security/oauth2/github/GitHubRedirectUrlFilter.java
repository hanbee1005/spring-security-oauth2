package nextstep.security.oauth2.github;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

public class GitHubRedirectUrlFilter extends GenericFilterBean {
    private static final String AUTHORIZATION_REQUEST_URL = "/oauth2/authorization/github";
    private static final String GITHUB_AUTHORIZATION_URL = "https://github.com/login/oauth/authorize?";
    public static final String REDIRECT_URL = "http://localhost:8080/login/oauth2/code/github";

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
                .queryParam("client_id", "Ov23liG6AMAwmGMmkYwT")
                .queryParam("response_type", "code")
                .queryParam("scope", "read:user")
                .queryParam("redirect_uri", REDIRECT_URL)
                .build()
                .toUri()
                .getQuery();

        response.sendRedirect(GITHUB_AUTHORIZATION_URL + queryParams);
    }
}
