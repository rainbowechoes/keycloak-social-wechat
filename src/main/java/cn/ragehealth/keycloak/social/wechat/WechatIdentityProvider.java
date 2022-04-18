package cn.ragehealth.keycloak.social.wechat;

import cn.hutool.http.HttpUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.util.UUID;

/**
 * <a href="https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419316505&token=2639bbef696c2f1540dec98ed4d45bcca460dd86&lang=zh_CN">参考文档</a>
 *
 * @author jacky.yong
 */
public class WechatIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    //第一步: 请求CODE
    public static final String AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";

    //第二步: 通过code获取access_token
    public static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";

    // 应用授权作用域，拥有多个作用域用逗号（,）分隔，网页应用目前仅填写snsapi_login即可
    public static final String DEFAULT_SCOPE = "snsapi_login";

    public static final String WECHAT_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";

    public static final String WECHAT_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";

    public static final String WECHAT_DEFAULT_SCOPE = "snsapi_userinfo";

    //第三步: 通过access_token调用 获取用户个人信息
    public static final String PROFILE_URL = "https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN";

    public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";

    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";

    public static final String WECHAT_APPID_KEY = "clientId2";

    public static final String WECHAT_APPID_SECRET = "clientSecret2";

    public static final String OPENID = "openid";

    public static final String WECHAT_USER_AGENT_FLAG = "micromessenger";

    public WechatIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
    }


    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }


    protected boolean supportsExternalExchange() {
        return true;
    }


    /**
     * 获取用户信息
     *
     * @param event
     * @param profile
     * @return
     */
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String unionid = getJsonProperty(profile, "unionid");

        BrokeredIdentityContext user = new BrokeredIdentityContext(
                (unionid != null && unionid.length() > 0 ? unionid : getJsonProperty(profile, "openid")));

        user.setUsername(getJsonProperty(profile, "openid"));
        user.setBrokerUserId(getJsonProperty(profile, "openid"));
        user.setModelUsername(getJsonProperty(profile, "openid"));
        user.setName(getJsonProperty(profile, "nickname"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    public BrokeredIdentityContext getFederatedIdentity(String response, boolean wechat) {
        String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }

        BrokeredIdentityContext context = null;
        try {
            JsonNode profile = null;
            if (wechat) {
                String openid = extractTokenFromResponse(response, "openid");
                String url = PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openid);

                profile = SimpleHttp.doGet(url, session).asJson();
            } else {
                profile = new ObjectMapper().readTree(response);
            }
            logger.info("get userInfo =" + profile.toString());
            context = extractIdentityFromProfile(null, profile);
        } catch (IOException e) {
            logger.error(e);
        }
        logger.info("context is null? ====>" + (context == null));

        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);

        return context;
    }


    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            String ua = request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase();
            if (isWechatBrowser(ua)) {
                return Response.seeOther(URI.create(authorizationUrl.toString() + "#wechat_redirect")).build();
            }
            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }


    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    /**
     * 判断是否在微信浏览器里面请求
     *
     * @param ua 浏览器user-agent
     * @return
     */
    private boolean isWechatBrowser(String ua) {
        String wechatAppId = getConfig().getConfig().get(WECHAT_APPID_KEY);
        String wechatSecret = getConfig().getConfig().get(WECHAT_APPID_SECRET);

        if (ua.indexOf(WECHAT_USER_AGENT_FLAG) > 0 && wechatAppId != null && wechatSecret != null
                && wechatAppId.length() > 0 && wechatSecret.length() > 0) {
            return true;
        }
        return false;
    }


    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

        final UriBuilder uriBuilder;
        String ua = request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase();
        if (isWechatBrowser(ua)) {
            // 是微信浏览器
            logger.info("----------wechat");
            uriBuilder = UriBuilder.fromUri(WECHAT_AUTH_URL);
            uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, WECHAT_DEFAULT_SCOPE)
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getConfig().get(WECHAT_APPID_KEY))
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        } else {
            uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
            uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        }

        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (getConfig().isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        String prompt = getConfig().getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = UUID.randomUUID().toString();
            request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }
        return uriBuilder;
    }

    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        @Context
        protected UriInfo uriInfo;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            if (state == null) {
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }

            try {
                AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
                session.getContext().setAuthenticationSession(authSession);

                if (error != null) {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    if (error.equals(ACCESS_DENIED)) {
                        return callback.cancelled();
                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                        return callback.error(error);
                    } else {
                        return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                if (authorizationCode != null) {
                    String response = getAccessTokenFromWx(authorizationCode);
                    logger.info("token response ====> " + response);
                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response, true);

                    if (getConfig().isStoreToken()) {
                        // make sure that token wasn't already set by getFederatedIdentity();
                        // want to be able to allow provider to set the token itself.
                        if (federatedIdentity.getToken() == null) {
                            federatedIdentity.setToken(response);
                        }
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(WechatIdentityProvider.this);
                    federatedIdentity.setAuthenticationSession(authSession);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }


        /**
         * 微信获取token
         * @param code
         * @return
         */
        public String getAccessTokenFromWx(String code){
            logger.info("config: " + getConfig());
            logger.info("config info: {}" + getConfig().getConfig());
            String appId = getConfig().getConfig().get("clientId");
            String appSecret = getConfig().getClientSecret();
            logger.info("wechat appId: " + appId);
            logger.info("wechat appSecret: " + appSecret);
            String path = "https://api.weixin.qq.com/sns/oauth2/access_token?appid="+ appId +"&secret="+ appSecret +"&code="+code+"&grant_type=authorization_code";
            return getRequest(path);
        }

        /**
         * get 请求
         * @param path
         * @return
         */
        public String getRequest(String path){
            return HttpUtil.get(path);
        }

    }
}
