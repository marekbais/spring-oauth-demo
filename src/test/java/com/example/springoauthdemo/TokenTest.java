package com.example.springoauthdemo;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TokenTest {
    public final static String AUTH_SERVER = "http://localhost:8080/auth";
    public final static String RESOURCE_SERVER = "http://localhost:8080/auth";

    @Test
    public void givenUser_whenUseFooClient_thenOkForFooResourceOnly() {
        final String accessToken = obtainAccessTokenWithAuthorizationCode("ClientId", "user", "pw");

        final Response fooResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken).get("http://localhost:8082/ui/secure");
        assertEquals(200, fooResponse.getStatusCode());
        System.out.println(accessToken);
    }

    private String obtainAccessTokenWithAuthorizationCode(String clientId, String username, String password) {
        final String redirectUrl = "http://localhost:8082/ui/secure";
        final String authorizeUrl = AUTH_SERVER + "/oauth/authorize?response_type=code&client_id=" + clientId + "&redirect_uri=" + redirectUrl;
        final String tokenUrl = AUTH_SERVER + "/oauth/token";

        // user login
        Response response = RestAssured.given().formParams("username", username, "password", password).post(AUTH_SERVER + "/login");
        final String cookieValue = response.getCookie("JSESSIONID");

        // get authorization code
        System.out.println(RestAssured.given().cookie("JSESSIONID", cookieValue).get(authorizeUrl).asString());
        Map<String, String> params = new HashMap<String, String>();
        params.put("user_oauth_approval", "true");
        params.put("authorize", "Authorize");
        params.put("scope.read", "true");
        response = RestAssured.given().cookie("JSESSIONID", cookieValue).formParams(params).post(authorizeUrl);
        assertEquals(HttpStatus.FOUND.value(), response.getStatusCode());

        final String location = response.getHeader(HttpHeaders.LOCATION);
        final String code = location.substring(location.indexOf("code=") + 5);

        // get access token
        params = new HashMap<String, String>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUrl);

        response = RestAssured.given().auth().basic(clientId, "secret").formParams(params).post(tokenUrl);
        return response.jsonPath().getString("access_token");
    }

}
