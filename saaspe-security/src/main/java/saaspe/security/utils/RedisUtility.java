
package saaspe.security.utils;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import com.google.gson.Gson;

@Component
public class RedisUtility {

	@Autowired
	private RedisTemplate<String, String> template;

	@Autowired
	private Gson gson;

	public void setValue(final String key, TokenCache cache, final Date date) {
		template.opsForValue().set(key, gson.toJson(cache));
		template.expireAt(key, date);
	}

	public TokenCache getValue(final String key) {
		return gson.fromJson(template.opsForValue().get(key), TokenCache.class);
	}

	public void deleteKeyformredis(String key) {
		template.delete(key);
	}
}
