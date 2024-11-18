package nextstep.security.oauth2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.oauth2.github.GithubProfileUser;
import nextstep.security.oauth2.google.GoogleProfileUser;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

public class Oauth2AuthenticationFilter extends GenericFilterBean {
    private static final String DEFAULT_LOGIN_REQUEST_BASE_URI = "/login/oauth2/code/";
    private final OAuth2ClientProperties oAuth2ClientProperties;

    private final OAuth2RequestClient oAuth2RequestClient = new OAuth2RequestClient();
    private final MemberRepository memberRepository = new InmemoryMemberRepository();
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public Oauth2AuthenticationFilter(OAuth2ClientProperties oAuth2ClientProperties) {
        this.oAuth2ClientProperties = oAuth2ClientProperties;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String registrationId = extractRegistrationId(request);
        if (registrationId == null) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        String code = request.getParameter("code");
        if (code == null) {
            throw new IllegalArgumentException("code가 없습니다.");
        }

        try {
            OAuth2ClientProperties.Provider provider = oAuth2ClientProperties.getProvider().get(registrationId);
            OAuth2ClientProperties.Registration registration = oAuth2ClientProperties.getRegistration().get(registrationId);

            String accessToken = oAuth2RequestClient.requestAccessToken(code, provider, registration);

            Class<? extends OAuth2ProfileUser> targetType = findProfileUserType(registration);
            OAuth2ProfileUser oAuth2ProfileUser = oAuth2RequestClient.requestUserProfile(accessToken, provider, targetType);

            Member member = memberRepository.findByEmail(oAuth2ProfileUser.getEmail())
                    .orElse(memberRepository.save(new Member(
                            oAuth2ProfileUser.getEmail(),
                            "",
                            oAuth2ProfileUser.getName(),
                            oAuth2ProfileUser.getImageUrl(),
                            Set.of("USER")))
                    );

            Authentication authentication
                    = UsernamePasswordAuthenticationToken.authenticated(member.getEmail(), null, member.getRoles());
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);

            response.setStatus(HttpServletResponse.SC_FOUND);
            response.addHeader("Location", "/");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\": \"Failed to authenticate with Oauth2\"}");
        }
    }

    private String extractRegistrationId(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (request.getMethod().equals("GET") && uri.startsWith(DEFAULT_LOGIN_REQUEST_BASE_URI)) {
            return uri.substring(DEFAULT_LOGIN_REQUEST_BASE_URI.length());
        }
        return null;
    }

    private Class<? extends OAuth2ProfileUser> findProfileUserType(OAuth2ClientProperties.Registration registration) {
        if (Objects.equals(registration.getProvider(), "github")) {
            return GithubProfileUser.class;
        }

        if (Objects.equals(registration.getProvider(), "google")) {
            return GoogleProfileUser.class;
        }

        throw new IllegalArgumentException("지원하지 않는 OAuth2 Provider 입니다.");
    }
}