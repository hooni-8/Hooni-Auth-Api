package org.hooni.auth.api.model.auth.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank
    @Size(min = 4, max = 30)
    @Pattern(regexp = "^[A-Za-z0-9]+$")
    private String userId;

    @NotBlank
    @Size(min = 8, max = 72)
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).+$")
    private String userPassword;

    @NotBlank
    @Size(max = 50)
    @Pattern(regexp = "^[^\\p{Cc}\\p{Cf}]+$")
    private String userName;
}
