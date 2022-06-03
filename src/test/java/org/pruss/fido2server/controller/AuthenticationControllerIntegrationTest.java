package org.pruss.fido2server.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthenticationControllerIntegrationTest {

    @Autowired
    private AuthenticationController controller;
    //    @Mock
//    MockHttpSession session = new MockHttpSession();
    @Autowired
    private MockMvc mockMvc;

    @Test
    public void contextLoads() {
        assertThat(controller).isNotNull();
    }

    @Test
    public void test_get_welcome() throws Exception {
        mockMvc.perform(
                        get("/")
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("FIDO2 Server Demo")));
    }

    @Test
    public void test_get_register() throws Exception {
        mockMvc.perform(
                        get("/register")
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Register Authentication")));
    }

    @Test
    public void test_post_register() throws Exception {
        mockMvc.perform(
                post("/register")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {"username": "testuser", "displayname": "testuser"
                                """)
        );
//                .andDo(print())
//                .andExpect(status().isOk())
//                .andExpect(content().string(containsString("Register Authentication")));
    }

}
