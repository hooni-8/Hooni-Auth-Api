package org.hooni.auth.api.mapper.auth;

import org.apache.ibatis.annotations.Mapper;
import org.hooni.auth.api.model.user.UserDetail;

@Mapper
public interface AuthMapper {

    UserDetail findByUserId(String userId);

    UserDetail findByUserCode(String userCode);

    boolean existsByUserId(String userId);

    int insert(UserDetail user);
}
