package saaspe.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/hi")
@RestController
public class UserLoginController {

	@GetMapping("/akash")
	@PreAuthorize("hasAuthority('VIEW_DEPARTMENT')")
	public String A() {
		try {
			return "Hi ra";
		} catch (Exception e) {
			return "how are you";
		}
	}

	@GetMapping("sathik")
	@PreAuthorize("hasAuthority('VIEW_DEPARTMENT')")
	public String B() {
		try {
			return "Hi ra";
		} catch (Exception e) {
			return "how are you";
		}
	}

	@GetMapping("/basha")
	@PreAuthorize("hasAuthority('VIEW_DEPARTMENT')")
	public String C() {
		try {
			return "Hi ra";
		} catch (Exception e) {
			return "how are you";
		}
	}

}
