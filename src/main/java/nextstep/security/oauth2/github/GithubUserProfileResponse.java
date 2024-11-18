package nextstep.security.oauth2.github;

public class GithubUserProfileResponse {
    private String email;
    private String avatarUrl;
    private String name;

    public String getEmail() {
        return email;
    }

    public String getAvatarUrl() {
        return avatarUrl;
    }

    public String getName() {
        return name;
    }
}
