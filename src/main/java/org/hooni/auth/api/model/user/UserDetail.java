package org.hooni.auth.api.model.user;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserDetail {

    private Long id;

    private String userCode;

    private String userId;

    private String userPw;

    private String userName;

    private String roleGroup;
}
