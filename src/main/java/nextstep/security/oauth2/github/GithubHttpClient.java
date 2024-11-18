package nextstep.security.oauth2.github;

import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class GithubHttpClient {
    private static final String GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";
    private static final String GITHUB_PROFILE_URL = "https://api.github.com/user";

    private final RestTemplate restTemplate = new RestTemplate();

    public String getAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        Map<String, String> body = new HashMap<>();
        body.put("client_id", "Ov23liTBhugSIcf8VX1v");
        body.put("client_secret", "your_client_secret");
        body.put("code", code);
        body.put("redirect_uri", GitHubRedirectUrlFilter.REDIRECT_URL);

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<GithubAccessTokenResponse> response
                = restTemplate.exchange(GITHUB_ACCESS_TOKEN_URL, HttpMethod.POST, request, GithubAccessTokenResponse.class);

        return Objects.requireNonNull(response.getBody()).getAccessToken();
    }

    public GithubUserProfileResponse requestUserProfile(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<GithubUserProfileResponse> response
                = restTemplate.exchange(GITHUB_PROFILE_URL, HttpMethod.GET, request, GithubUserProfileResponse.class);
        return response.getBody();
    }
}
