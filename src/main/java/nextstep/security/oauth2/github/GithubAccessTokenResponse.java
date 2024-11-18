package nextstep.security.oauth2.github;

public class GithubAccessTokenResponse {
    private String accessToken;
    private String scope;
    private String tokenType;

    public String getAccessToken() {
        return accessToken;
    }
}
