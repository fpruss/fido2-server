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
import org.pruss.fido2server.service.RelyingPartyService;
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

    private final RelyingPartyService relyingPartyService;
    private final RegistrationService registrationService;
    private final ApplicationUserService userService;
    private AuthenticatorService authenticatorService;

    @GetMapping("/")
    public String welcome() {
        return "index";
    }

    @GetMapping("/register")
    public String registerUser(Model model) {
        return "register";
    }

    @PostMapping("/register")
    @ResponseBody
    public String saveNewUserAndGetPublicKeyCredentialCreationOptions(@RequestParam String username, @RequestParam String displayName, HttpSession session) {
        if (userService.exists(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + username + " already exists. Choose a new name.");
        }

        ApplicationUser user = userService.createApplicationUser(username, displayName);
        userService.save(user);

        return getPublicKeyCredentialCreationOptions(user, session);
    }

    @PostMapping("/registerauth")
    @ResponseBody
    public String getPublicKeyCredentialCreationOptions(@RequestParam ApplicationUser user, HttpSession session) {
        if (userService.doesNotExist(user)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User " + user.getUsername() + " does not exist. Please register.");
        }

        PublicKeyCredentialCreationOptions credentialCreationOptions =
                registrationService.createPublicKeyCredentialCreationOptions(user.toUserIdentity());
        session.setAttribute(user.getDisplayName(), credentialCreationOptions);

        try {
            return credentialCreationOptions.toCredentialsCreateJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error processing JSON.", e);
        }
    }

    @PostMapping("/finishauth")
    @ResponseBody
    public ModelAndView finishRegistration(@RequestParam String credential, @RequestParam String username, @RequestParam String credentialName, HttpSession session) {
        try {
            ApplicationUser user = userService.getUser(username).orElseThrow(NullPointerException::new);
            Authenticator finalizedAuthenticator = registrationService.finishRelyingPartyRegistration(user, session, credential, credentialName);
            authenticatorService.save(finalizedAuthenticator);
            return new ModelAndView("redirect:/login", HttpStatus.SEE_OTHER);
        } catch (RegistrationFailedException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration failed.", e);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to save credential, please try again!", e);
        } catch (NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Cached request expired. Try to register again!");
        }
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    @ResponseBody
    public String startLogin(@RequestParam String username, HttpSession session) {
        AssertionRequest request = relyingPartyService.buildAssertionRequest(username);
        try {
            session.setAttribute(username, request);
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/welcome")
    public String finishLogin(@RequestParam String credential, @RequestParam String username, Model model, HttpSession session) {
        try {
            AssertionResult result = relyingPartyService.buildAssertionResult(credential, username, session);
            if (result.isSuccess()) {
                model.addAttribute("username", username);
                return "welcome";
            } else {
                return "index";
            }
        } catch (IOException | AssertionFailedException e) {
            throw new RuntimeException("Authentication failed", e);
        }
    }
}