package nextstep.security.oauth2.google;

import nextstep.security.oauth2.github.GitHubRedirectUrlFilter;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class GoogleHttpClient {
    private static final String GOOGLE_ACCESS_TOKEN_URL = "https://accounts.google.com/o/oauth2/token";
    private static final String GOOGLE_PROFILE_URL = "https://www.googleapis.com/oauth2/v1/userinfo";

    private final RestTemplate restTemplate = new RestTemplate();

    public String getAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        Map<String, String> body = new HashMap<>();
        body.put("client_id", "88951150265-q7aq5urrim4rrtqo62hc96o6r5v7r34c.apps.googleusercontent.com");
        body.put("client_secret", "your_client_secret");
        body.put("code", code);
        body.put("redirect_uri", GitHubRedirectUrlFilter.REDIRECT_URL);
        body.put("grant_type", "authorization_code");

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<GoogleAccessTokenResponse> response
                = restTemplate.exchange(GOOGLE_ACCESS_TOKEN_URL, HttpMethod.POST, request, GoogleAccessTokenResponse.class);

        return Objects.requireNonNull(response.getBody()).getAccessToken();
    }

    public GoogleUserProfileResponse requestUserProfile(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<GoogleUserProfileResponse> response
                = restTemplate.exchange(GOOGLE_PROFILE_URL, HttpMethod.GET, request, GoogleUserProfileResponse.class);
        return response.getBody();
    }
}
