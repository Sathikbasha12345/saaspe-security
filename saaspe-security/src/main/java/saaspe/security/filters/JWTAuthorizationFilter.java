package saaspe.security.filters;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import saaspe.security.configuration.AzureConfig;
import saaspe.security.constant.Constant;
import saaspe.security.entity.UserLoginDetails;
import saaspe.security.model.GraphGroupsResponse;
import saaspe.security.model.Value;
import saaspe.security.utils.EncryptionHelper;
import saaspe.security.utils.RedisUtility;
import saaspe.security.utils.TokenCache;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	private String encryptionKey;
	private String jwtKey;
	private RedisUtility redisUtility;
	private RestTemplate restTemplate;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, String encryptionKey, String jwtKey,
			RedisUtility redisUtility) {
		super(authenticationManager);
		this.restTemplate = new RestTemplate();
		this.redisUtility = redisUtility;
		this.encryptionKey = encryptionKey;
		this.jwtKey = jwtKey;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String header = request.getHeader(Constant.HEADER_STRING);
		if (header == null || !header.startsWith(Constant.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		try {
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
			if (authentication != null) {
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			chain.doFilter(request, response);
		} catch (BadCredentialsException e) {
			sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "UNAUTHORIZED", e.getLocalizedMessage());
		}
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request)
			throws javax.security.sasl.AuthenticationException {
		String token = request.getHeader(Constant.HEADER_STRING);
		String provider = request.getHeader(Constant.HEADER_PROVIDER_STRING);

		if (provider == null || provider.equalsIgnoreCase(Constant.HEADER_PROVIDER_NAME)) {
			return verifyToken(token);
		} else if (provider.equalsIgnoreCase("azure")) {
			return authenticateAzureUser(token);
		} else {
			throw new BadCredentialsException("Vendor Should be in the list or Vendor is Null");
		}
	}

	private UsernamePasswordAuthenticationToken verifyToken(String token) {
		if (token != null) {
			try {
				DecodedJWT jwt = JWT
						.require(Algorithm.HMAC256(EncryptionHelper.decrypt(encryptionKey, jwtKey).getBytes())).build()
						.verify(token.replace(Constant.TOKEN_PREFIX, ""));
				String user = jwt.getSubject();
				if (user != null) {
					Set<SimpleGrantedAuthority> authorities = extractAuthoritiesFromToken(jwt);
					UserLoginDetails profile = new UserLoginDetails();
					profile.setEmailAddress(jwt.getClaim("email").asString());
					return new UsernamePasswordAuthenticationToken(profile, null, authorities);
				}
			} catch (JWTVerificationException e) {
				throw new BadCredentialsException("Invalid Token");
			}
		}
		return null;
	}

	private Set<SimpleGrantedAuthority> extractAuthoritiesFromToken(DecodedJWT jwt) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		String scopes = jwt.getClaim("scopes").asString();
		List<String> scopesList = new ArrayList<>(Arrays.asList(scopes.split(", ")));
		for (String scope : scopesList) {
			authorities.add(new SimpleGrantedAuthority(scope));
		}
		authorities.add(new SimpleGrantedAuthority(jwt.getClaim("role").asString()));
		return authorities;
	}

	private UsernamePasswordAuthenticationToken authenticateAzureUser(String token) {
		if (token != null) {
			DecodedJWT jwt = JWT.decode(token.replace("Bearer ", ""));
			String email = jwt.getClaim("upn").asString();
			TokenCache cacheValue = redisUtility.getValue(email);
			TokenCache docChcek = redisUtility.getValue("token" + email);
			if (cacheValue == null) {
				validateAzureToken(token);
				GraphGroupsResponse groupsResponse = fetchUserGroups(token);
				boolean isUser = isUserInGroup(groupsResponse, "clm-users");
				if (isUser) {
					Set<SimpleGrantedAuthority> authorities = new HashSet<>();
					List<String> scopesList = new ArrayList<>(Arrays.asList(Constant.ROLE_CLM.split(", ")));
					for (String scope : scopesList) {
						authorities.add(new SimpleGrantedAuthority(scope));
					}
					TokenCache cache = new TokenCache();
					cache.setEmailAddress(email);
					cache.setDisplayname("clm-user");
					cache.setExpiryDate(jwt.getExpiresAt());
					cache.setToken(token.replace("Bearer ", ""));
					redisUtility.setValue(email, cache, jwt.getExpiresAt());
					if (docChcek == null) {
						yourMethodToNotify(token);
						TokenCache docCache = new TokenCache();
						docCache.setEmailAddress("token" + email);
						docCache.setDisplayname("clm-user");
						docCache.setExpiryDate(jwt.getExpiresAt());
						docCache.setToken(token.replace("Bearer ", ""));
						redisUtility.setValue("token" + email, docCache, jwt.getExpiresAt());
					}
					UserLoginDetails profile = new UserLoginDetails();
					profile.setEmailAddress(jwt.getClaim("email").asString());
					return new UsernamePasswordAuthenticationToken(profile, null, authorities);
				} else {
					throw new BadCredentialsException("User Not present in the group");
				}
			} else {
				validateAzureToken(token);
				if (docChcek == null) {
					yourMethodToNotify(token);
					TokenCache docCache = new TokenCache();
					docCache.setEmailAddress("token" + email);
					docCache.setDisplayname("clm-user");
					docCache.setExpiryDate(jwt.getExpiresAt());
					docCache.setToken(token.replace("Bearer ", ""));
					redisUtility.setValue("token" + email, docCache, jwt.getExpiresAt());
				}
				Set<SimpleGrantedAuthority> authorities = new HashSet<>();
				List<String> scopesList = new ArrayList<>(Arrays.asList(Constant.ROLE_CLM.split(", ")));
				for (String scope : scopesList) {
					authorities.add(new SimpleGrantedAuthority(scope));
				}
				UserLoginDetails profile = new UserLoginDetails();
				profile.setEmailAddress(jwt.getClaim("email").asString());
				return new UsernamePasswordAuthenticationToken(profile, null, authorities);
			}
		}
		return null;
	}

	private void validateAzureToken(String token) {
		boolean valid = AzureConfig.isValidToken(token);
		if (!valid) {
			throw new BadCredentialsException("Token Already Expired");
		}
	}

	public void yourMethodToNotify(String message) {
		Map<String, String> userDetails = getUserDetailsForSSOUser(message);
		getClmUsersList(userDetails.get("email"), userDetails.get("firstName"), userDetails.get("lastName"));
	}

	private void getClmUsersList(String userEmail, String firstName, String lastName) {
		URI uri = UriComponentsBuilder.fromUriString("http://saaspe-docusign-svc:8085/users")
				.queryParam("userEmail", userEmail).queryParam("firstName", firstName).queryParam("lastName", lastName)
				.build().toUri();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.TEXT_PLAIN);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		ResponseEntity<String> response = restTemplate.exchange(uri, HttpMethod.GET, entity, String.class);
	}

	private Map<String, String> getUserDetailsForSSOUser(String token) {
		Map<String, String> userDetails = new HashMap<>();
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.setBearerAuth(token.replace("Bearer ", ""));
		HttpEntity<String> entity = new HttpEntity<>(headers);
		ResponseEntity<String> response = restTemplate.exchange(Constant.GRAPH_GROUP_URL_ME, HttpMethod.GET, entity,
				String.class);
		String responseBody = response.getBody();
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode rootNode = null;
		try {
			rootNode = objectMapper.readTree(responseBody);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		userDetails.put("displayName", rootNode.get("displayName").asText());
		userDetails.put("firstName", rootNode.get("surname").asText());
		userDetails.put("email", rootNode.get("mail").asText());
		userDetails.put("lastName", rootNode.get("givenName").asText());
		return userDetails;
	}

	private GraphGroupsResponse fetchUserGroups(String token) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.setBearerAuth(token.replace("Bearer ", ""));
		HttpEntity<String> entity = new HttpEntity<>(headers);
		ResponseEntity<GraphGroupsResponse> response = restTemplate.exchange(Constant.GRAPH_GROUP_URL, HttpMethod.GET,
				entity, GraphGroupsResponse.class);
		return response.getBody();
	}

	private boolean isUserInGroup(GraphGroupsResponse groupsResponse, String groupId) {
		for (Value value : groupsResponse.getValue()) {
			if (value.getDisplayName().equalsIgnoreCase(groupId)) {
				return true;
			}
		}
		return false;
	}

	private void sendErrorResponse(HttpServletResponse response, int statusCode, String status, String message)
			throws IOException {
		response.setStatus(statusCode);
		response.setContentType("application/json");
		Map<String, String> object = new HashMap<>();
		object.put("message", message);
		object.put("status", status);
		String json = new Gson().toJson(object);
		response.getWriter().write(json);
	}

}