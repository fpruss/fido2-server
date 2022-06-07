package org.pruss.fido2server.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.AllArgsConstructor;
import org.pruss.fido2server.data.ApplicationUser;
import org.pruss.fido2server.data.Authenticator;
import org.pruss.fido2server.service.ApplicationUserService;
import org.pruss.fido2server.service.AuthenticatorService;
import org.pruss.fido2server.service.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.io.IOException;

@Controller
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class AuthenticationController {

    private final RegistrationService registrationService;
    private final ApplicationUserService userService;
    private AuthenticatorService authenticatorService;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/register/begin")
    public String registerUser(Model model) {
        return "register";
    }

    @PostMapping("/register/begin")
    @ResponseBody
    public String beginRegistration(
            @RequestParam String username,
            @RequestParam String displayName,
            HttpSession session) {
        userService.requireDoesNotExist(username);
        ApplicationUser user = userService.createApplicationUser(username, displayName);
        userService.save(user);
        return getPublicKeyCredentialCreationOptions(user, session);
    }

    private String getPublicKeyCredentialCreationOptions(ApplicationUser user, HttpSession session) {
        userService.requireExists(user);
        PublicKeyCredentialCreationOptions credentialCreationOptions =
                registrationService.createPublicKeyCredentialCreationOptions(user.toUserIdentity());
        session.setAttribute(user.getDisplayName(), credentialCreationOptions);

        try {
            return credentialCreationOptions.toCredentialsCreateJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error processing JSON.", e);
        }
    }

    @PostMapping("/register/finish")
    @ResponseBody
    public ModelAndView finishRegistration(
            @RequestParam String credential,
            @RequestParam String username,
            HttpSession session) {
        try {
            ApplicationUser user = userService.getUser(username).orElseThrow(NullPointerException::new);
            Authenticator finalizedAuthenticator = registrationService.finishRelyingPartyRegistration(user, session, credential);
            authenticatorService.save(finalizedAuthenticator);
            return new ModelAndView("redirect:/login/begin", HttpStatus.SEE_OTHER);
        } catch (RegistrationFailedException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration failed.", e);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to save credential, please try again!", e);
        } catch (NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Cached request expired. Try to register again!");
        }
    }

    @GetMapping("/login/begin")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login/begin")
    @ResponseBody
    public String startLogin(@RequestParam String username, HttpSession session) {
        AssertionRequest request = registrationService.buildAssertionRequest(username);
        try {
            session.setAttribute(username, request);
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/login/finish")
    public String finishLogin(@RequestParam String credential, @RequestParam String username, Model model, HttpSession session) {
        try {
            AssertionResult result = registrationService.buildAssertionResult(credential, username, session);
            if (result.isSuccess()) {
                model.addAttribute("username", username);
                return "welcome";
            }
            return "index";
        } catch (IOException | AssertionFailedException e) {
            throw new RuntimeException("Authentication failed", e);
        }
    }
}