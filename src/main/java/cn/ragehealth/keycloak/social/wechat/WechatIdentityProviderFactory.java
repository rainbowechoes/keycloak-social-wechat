package cn.ragehealth.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * @author jacky.yong
 */
public class WechatIdentityProviderFactory extends AbstractIdentityProviderFactory<WechatIdentityProvider>
        implements SocialIdentityProviderFactory<WechatIdentityProvider> {

    public static final String PROVIDER_ID = "wechat";

    public String getName() {
        return "Wechat";
    }

    public WechatIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WechatIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    public String getId() {
        return PROVIDER_ID;
    }
}
