package nextstep.security.oauth2.google;

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
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Set;

public class GoogleAuthorizationFilter extends GenericFilterBean {
    private static final String AUTHORIZATION_REQUEST_URL = "/login/oauth2/code/google";

    private final GoogleHttpClient googleHttpClient = new GoogleHttpClient();
    private final MemberRepository memberRepository = new InmemoryMemberRepository();
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (!request.getMethod().equals("GET")
                || !request.getRequestURI().startsWith(AUTHORIZATION_REQUEST_URL)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        try {
            String accessToken = googleHttpClient.getAccessToken(request.getParameter("code"));
            GoogleUserProfileResponse profile = googleHttpClient.requestUserProfile(accessToken);

            Member member = memberRepository.findByEmail(profile.getEmail()).orElse(
                    memberRepository.save(
                            new Member(
                                    profile.getEmail(),
                                    null,
                                    profile.getName(),
                                    profile.getPicture(),
                                    Set.of("USER")
                            )
                    )
            );

            Authentication authentication = UsernamePasswordAuthenticationToken
                    .authenticated(member.getEmail(), null, member.getRoles());

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);

            response.setStatus(HttpServletResponse.SC_FOUND);
            response.addHeader("Location", "/");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\": \"Failed to authenticate with Google\"}");
        }
    }
}
