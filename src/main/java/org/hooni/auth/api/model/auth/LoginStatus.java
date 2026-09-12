package org.hooni.auth.api.model.auth;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LoginStatus {

    private final boolean status;

    /** Access Token은 없지만 검증된 Refresh 세션으로 복구할 수 있는지 나타낸다. */
    private final boolean refreshable;

    private final String userCode;

    private final String name;

    private final String role;
}
