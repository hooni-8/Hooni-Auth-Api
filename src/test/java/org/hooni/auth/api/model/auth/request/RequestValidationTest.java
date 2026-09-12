package org.hooni.auth.api.model.auth.request;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequestValidationTest {
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    void rejectsOversizedLoginPassword() {
        LoginRequest request = new LoginRequest();
        request.setUserId("validuser");
        request.setPassword("a".repeat(73));

        assertThat(validator.validate(request)).isNotEmpty();
    }

    @Test
    void acceptsAlphanumericUserIdForRegistrationAndLogin() {
        LoginRequest login = new LoginRequest();
        login.setUserId("validuser1");
        login.setPassword("password1");
        RegisterRequest register = new RegisterRequest();
        register.setUserId("validuser1");
        register.setUserPassword("password1");
        register.setUserName("Valid User");

        assertThat(validator.validate(login)).isEmpty();
        assertThat(validator.validate(register)).isEmpty();
    }

    @Test
    void rejectsSpecialCharactersInEveryUserIdRequest() {
        LoginRequest login = new LoginRequest();
        login.setUserId("invalid_user");
        login.setPassword("password1");
        RegisterRequest register = new RegisterRequest();
        register.setUserId("invalid-user");
        register.setUserPassword("password1");
        register.setUserName("Valid User");
        RegisterExistsIdRequest exists = new RegisterExistsIdRequest();
        exists.setUserId("invalid_user");

        assertThat(validator.validate(login)).isNotEmpty();
        assertThat(validator.validate(register)).isNotEmpty();
        assertThat(validator.validate(exists)).isNotEmpty();
    }

    @Test
    void rejectsRegisterRequestThatOnlyFrontEndWouldHaveRejected() {
        RegisterRequest request = new RegisterRequest();
        request.setUserId("invalid user id");
        request.setUserPassword("password-without-number");
        request.setUserName("Valid Name");

        assertThat(validator.validate(request)).hasSizeGreaterThanOrEqualTo(2);
    }
}
