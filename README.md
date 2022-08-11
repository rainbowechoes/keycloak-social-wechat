# keycloak 微信第三方登录

对 keycloak 15.0.0 版本实现了微信第三方登录。

优先获取用户 unionid 作为 keycloak 用户 username(即 keycloak 中的唯一标识)，如果没有，则以 openid 作为唯一标识

# 使用方式

1. 进入容器

```shell
docker exec -it keycloak /bin/bash
```

创建 providers 目录，并具备对应权限
```shell
mkdir -p /opt/jboss/keycloak/providers/
chown jboss:root /opt/jboss/keycloak/providers/
chmod 755 /opt/jboss/keycloak/providers/
```

2. 将文件放入容器

```shell
docker cp keycloak-social-wechat-15.0.0-jar-with-dependencies.jar keycloak:/opt/jboss/keycloak/providers/
docker cp templates/realm-identity-provider-wechat.html keycloak:/opt/jboss/keycloak/themes/base/admin/resources/partials
docker cp templates/realm-identity-provider-wechat-ext.html keycloak:/opt/jboss/keycloak/themes/base/admin/resources/partials
docker restart keycloak
```

3. 创建 realm，添加 provider

