package com.barrhopp.api.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * End-to-end auth tests against a real PostGIS instance (not H2), so the
 * Flyway migrations - including V1's PostGIS check - run exactly as in prod.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGIS = new PostgreSQLContainer<>(
        DockerImageName.parse("postgis/postgis:16-3.4").asCompatibleSubstituteFor("postgres"));

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGIS::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGIS::getUsername);
        registry.add("spring.datasource.password", POSTGIS::getPassword);
        registry.add("jwt.secret", () -> "integration-test-secret-at-least-32-chars-long");
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private static String body(String email, String password, String name) {
        return """
            {"email":"%s","password":"%s","displayName":"%s"}""".formatted(email, password, name);
    }

    private static String login(String email, String password) {
        return """
            {"email":"%s","password":"%s"}""".formatted(email, password);
    }

    @Test
    void registerReturnsTokenAndNeverLeaksPasswordHash() throws Exception {
        String response = mvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body("Alice@Example.com", "correct-horse", "Alice")))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.tokenType").value("Bearer"))
            .andExpect(jsonPath("$.user.email").value("alice@example.com")) // normalized
            .andExpect(jsonPath("$.user.role").value("USER"))
            .andReturn().getResponse().getContentAsString();

        assertThat(response).doesNotContain("password");
    }

    @Test
    void duplicateEmailIsConflictEvenWithDifferentCase() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(body("bob@example.com", "correct-horse", "Bob")))
            .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(body("BOB@example.com", "another-pass1", "Bob 2")))
            .andExpect(status().isConflict());
    }

    @Test
    void invalidRegistrationReturnsFieldErrors() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(body("not-an-email", "short", "")))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errors.email").exists())
            .andExpect(jsonPath("$.errors.password").exists())
            .andExpect(jsonPath("$.errors.displayName").exists());
    }

    @Test
    void loginSucceedsThenTokenUnlocksProtectedEndpoint() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(body("carol@example.com", "correct-horse", "Carol")))
            .andExpect(status().isCreated());

        String loginResponse = mvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(login("carol@example.com", "correct-horse")))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        JsonNode node = json.readTree(loginResponse);
        String token = node.get("accessToken").asText();

        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("carol@example.com"))
            .andExpect(jsonPath("$.displayName").value("Carol"));
    }

    @Test
    void wrongPasswordAndUnknownEmailGiveIdenticalUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(body("dave@example.com", "correct-horse", "Dave")))
            .andExpect(status().isCreated());

        String wrongPassword = mvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(login("dave@example.com", "nope-nope-nope")))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        String unknownUser = mvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(login("ghost@example.com", "whatever-pass")))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        // Same body either way: the endpoint must not reveal which emails exist.
        assertThat(wrongPassword).isEqualTo(unknownUser);
    }

    @Test
    void protectedEndpointRejectsMissingAndGarbageTokens() throws Exception {
        mvc.perform(get("/api/v1/auth/me"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.detail").value("Authentication required"));

        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer not.a.jwt"))
            .andExpect(status().isUnauthorized());
    }
}
