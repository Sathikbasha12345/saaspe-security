package saaspe.security.constant;

public class Constant {

	private Constant() {
		super();
	}

	public static final String HEADER_PROVIDER_NAME = "Internal";
	public static final String HEADER_PROVIDER_STRING = "X-Auth-Provider";
	public static final String GRAPH_GROUP_URL_ME = "https://graph.microsoft.com/v1.0/me";
	public static final String GRAPH_GROUP_URL = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group";

	public static final String ROLE_SUPER_ADMIN = "VIEW_USER, VIEW_APPLICATION, VIEW_DEPARTMENT, VIEW_ONBOARDINGMGMT, REVIEW_ONBOARDINGMGMT, APPROVE_ONBOARDINGMGMT, ADD_ADMINUSER, VIEW_ADMINUSER, EDIT_ADMINUSER, DELETE_ADMINUSER, ADD_MULTICLOUD, EDIT_MULTICLOUD, DELETE_MULTICLOUD, VIEW_MULTICLOUD, ADD_INVOICE, DELETE_INVOICE, VIEW_PROJECT, VIEW_INTEGRATION, VIEW_DASHBOARD, VIEW_INVOICE, VIEW_SUBSCRIPTION, VIEW_MARKETPLACE, VIEW_CONTRACT, EDIT_CURRENCY, CREATE_BUDGET";
	public static final String ROLE_REVIEWER = "VIEW_USER, VIEW_APPLICATION, VIEW_DEPARTMENT, VIEW_ONBOARDINGMGMT, REVIEW_ONBOARDINGMGMT, APPROVE_ONBOARDINGMGMT, VIEW_MULTICLOUD, VIEW_PROJECT, VIEW_INTEGRATION, VIEW_DASHBOARD, VIEW_INVOICE, VIEW_SUBSCRIPTION, VIEW_MARKETPLACE, VIEW_CONTRACT";
	public static final String ROLE_APPROVER = "VIEW_USER, VIEW_APPLICATION, VIEW_DEPARTMENT, VIEW_ONBOARDINGMGMT, REVIEW_ONBOARDINGMGMT, APPROVE_ONBOARDINGMGMT, VIEW_MULTICLOUD, VIEW_PROJECT, VIEW_INTEGRATION, VIEW_DASHBOARD, VIEW_INVOICE, VIEW_SUBSCRIPTION, VIEW_MARKETPLACE, VIEW_CONTRACT";
	public static final String ROLE_CONTRIBUTOR = "VIEW_USER, VIEW_APPLICATION, VIEW_DEPARTMENT, ADD_USER, ADD_APPLICATION, ADD_DEPARTMENT, EDIT_USER, EDIT_APPLICATION, EDIT_DEPARTMENT, DELETE_USER, DELETE_APPLICATION, DELETE_DEPARTMENT, VIEW_REQUESTMGMT, ENABLE_INTEGRATION, REMOVE_INTEGRATION, MAP_INTEGRATION, VIEW_MULTICLOUD, VIEW_INTEGRATION, VIEW_DASHBOARD, VIEW_INVOICE, VIEW_SUBSCRIPTION, VIEW_PROJECT, EDIT_PROJECT, VIEW_MARKETPLACE, VIEW_CONTRACT, ADD_CONTRACT, EDIT_CONTRACT, ADD_PROJECT";
	public static final String ROLE_SUPPORT = "ADD_WORKFLOW, EDIT_WORKFLOW, VIEW_WORKFLOW, VIEW_USER, VIEW_APPLICATION, VIEW_DEPARTMENT, VIEW_MULTICLOUD, VIEW_PROJECT, VIEW_INTEGRATION, VIEW_DASHBOARD, VIEW_INVOICE, VIEW_SUBSCRIPTION, VIEW_MARKETPLACE, VIEW_CONTRACT, ADD_INVOICE, DELETE_INVOICE";
	public static final String ROLE_CUSTOM = "VIEW_USER, VIEW_APPLICATION, VIEW_DEPARTMENT, VIEW_REQUESTMGMT, VIEW_MULTICLOUD, VIEW_INTEGRATION, VIEW_DASHBOARD, VIEW_INVOICE, VIEW_SUBSCRIPTION, VIEW_PROJECT, VIEW_MARKETPLACE, VIEW_CONTRACT";
	public static final String ROLE_CLM = "VIEW_CONTRACT, ADD_CONTRACT, EDIT_CONTRACT";

	public static final int EMAIL_VERIFICATION_CODE_EXPIRE_DATE = 2880;

	public static final String USER_ID_ERROR_MESSAGE = "UserId or EmailAddress must be valid";
	public static final String USER_ID_ERROR_KEY = "userId";
	public static final String VERIFY_INITIATE_URL = "/api/userprofile/verify-initiate";
	public static final String RESET_INITIATE_URL = "/api/userprofile/reset-initiate";
	public static final String VERIFY_EMAIL_ERROR_KEY = "emailAddress";
	public static final String VERIFY_EMAIL_ERROR_MESSAGE = "Email is already verified";

	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
	public static final String SIGN_UP_URL = "/api/userprofile/signup";
	public static final String LOGIN_URL = "/api/userprofile/login";
	public static final String RESET_PASSWORD_URL = "/api/userprofile/reset-password";
	public static final String VERIFY_EMAIL_URL = "/api/userprofile/verify-email";
	public static final String VERIFY_OTP = "/api/userprofile/verify-otp";
	public static final String CREATE_PASSWORD = "/api/auth/create-password";
	public static final String REFRESH_TOKEN = "/api/userprofile/refresh/token";
	public static final String DOCUSIGN_EVENTS = "/docusign/events";
	public static final String ENQUIRY = "/api/enquiry";

	public static final String CONFIRM_PASSWORD_ERROR_MESSAGE = "Password and Confirm Password don't match";
	public static final String NEW_PASSWORD_EQUALS_OLD_PASSWORD_ERROR_MESSAGE = "New Password cannot be the same as Old Password";

	public static final String BUID = "BUID_01";

	public static final String URL_ERROR = "URL Error";

	public static final String UNABLE_TO_CONNECT_TO_AZURE = "Unable to Connect to Azure, Please Check URL in properties";

	public static final String START_TIME = "startTime";

	public static final String END_TIME = "endTime";

	public static final String TIME_TAKEN = "timeTaken";

	public static final String AUTH_CODE = "auth_code";
	public static final String DEV = "dev";

}
