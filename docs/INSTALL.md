# How To Install

Download the latest released version and upload to your Mattermost installation on the plugins page of the System Console in the usual way.

## How To Configure

### Prerequisites

1. Setup SAML login with Keycloak, see our guide [here](https://docs.mattermost.com/onboard/sso-saml-keycloak.html). 
2. Create groups in your Keycloak realm, see the official documentation [here](https://www.keycloak.org/docs/latest/server_admin/index.html#proc-managing-groups_server_administration_guide).

### Keycloak Setup

This guide will break down the setup into 4 easy stages:
1. [Keycloak service account setup](#keycloak-service-account-setup)
2. [Mattermost plugin configuration](#mattermost-plugin-configuration)
3. [Keycloak group membership attribute](#keycloak-group-membership-attribute)
4. [Mattermost group link and syncables setup](#mattermost-group-link-and-syncables-setup)

#### Keycloak service account setup

In addition to setting up SAML login you will also need to configure a service account for the plugin to use. You will need to create this client in the same realm as your SAML login client.

1. Navigate to your realm and click **Create Client**.
2. Configure the following values for step 1:
```
Client type: OpenID Connect
Client ID:   mattermost-admin
```
![Client creation step 1](./assets/client-creation-step-1.png)

3. Click next and configure the following values: 
```
Client authentication: Enabled
Service account roles: Enabled
```
![Client creation step 2](./assets/client-creation-step-2.png)

4. Disable the other configurations, click next and then Save.
5. The client is now created but we need to assign a role to the service account so it can view the groups in our realm. Navigate to **Service account roles**.
![Service account roles page](./assets/service-account-roles.png)

6. Click **Assign role**, in the modal click the dropdown that says **Filter by realm roles** and click **Filter by clients**.
![Service account roles modal](./assets/assign-roles-modal.png)

7. A new list of roles will appear, select **realm-admin** and click **Assign**.
8. Navigate to the **Advanced** section to enable refresh tokens. This is not necessary but will be helpful for troubleshooting roles when configuring the plugin because this allows service account sessions to be revoked directly from Keycloak.
9. Scroll to the **Open ID Connect Compatibility Modes** section and enabled the following values:
```
Use refresh tokens for client credentials grant: Enabled
```
![Keycloak refresh tokens](./assets/keycloak-refresh-tokens.png)

10. Click save on that section.
11. Scroll down to the **Advanced settings** section.
12. Set the **Access Token Lifespan** value to hours or days. This is not necessary but it means less calls to the authenticate endpoint.
13. Click save on that section.
14. Click the credentials tab and set **Client authenticator** to **Client Id and Secret**.
15. Regenerate and copy the **Client Secret**.

#### Mattermost plugin configuration

In this step we will configure the Identity groups sync plugin configurations and view your Keycloak groups inside Mattermost.

1. In system console navigate to **Identity Groups Sync** in the **PLUGINS** section.
2. Configure the following values:
```
Groups Provider:        Keycloak
At Rest Encryption Key: <Click regenerate>
Keycloak Host URL:      <Your keycloak hostname>
Keycloak Realm:         <Your keycloak realm>
Client ID:              mattermost-admin
Client Secret:          <Paste the value from step 9 of Keycloak service account setup>
Groups Attribute:       memberOf
```
![System console configurations](./assets/system-console-configs.png)

3. Click Save. At this stage your plugin is configured to view Keycloak groups inside Mattermost system console, the next steps will confirm this.
4. In system console navigate to the **Groups** page.
5. Confirm there is a section that says **Keycloak Groups** and you can see a list of your Keycloak groups. If you cannot see your Keycloak groups inside Mattermost, skip to the troubleshooting section.
![Keycloak groups](./assets/mattermost-groups.png)
6. In Keycloak you can **disable** the **Use refresh tokens for client credentials grant** configuration if you please, we have confirmed the correct role setting has been granted. Keycloak says the following about Refresh tokens for client credential grants:
```
The OAuth 2.0 RFC6749 Section 4.4.3 states that a refresh_token should not be generated when client_credentials grant is used. If this is off then no refresh_token will be generated and the associated user session will be removed.
```

### Keycloak group membership attribute

In order for a user's group memberships to sync with Mattermost they need to be included in the SAML attributes when they login.

1. In Keycloak navigate to your Mattermost SAML client.
2. Click **Client scopes**.
3. Click **mattermost-dedicated**.
4. Click **Add mapper** and then **By configuration**.
5. Click **Group list** as your configured mapper.
6. Configure your group mapper with the following values:
```
Name:                       GroupList
Group attribute name:       memberOf
Friendly name:
SAML Attribute Name Format: Basic
Single Group Attribute:     Enabled
Full group path:            Disabled
```
**Group attribute name** needs to match the Groups Attribute value you set in your plugin configurations in Mattermost

![Keycloak mapper](./assets/keycloak-group-mapper.png)

7. Click save.

### Mattermost group link and syncables setup

In this step we will link a Keycloak group to Mattermost, assign it to a channel and sign in as a SAML user.

1. Navigate to the **Groups** section of system console.
2. Select a group from your Keycloak groups list and click **Link Selected Group**. This creates a **UserGroup** record in the Mattermost database.
3. Now we need to link this group to a channel. Navigate to **Channels** in system console.
4. Select the channel you want to assign the group to.
5. In order to make a channel only accessible to assigned groups you need to enable **Sync Group Members**. This will change the channel to private and remove any non group members from the channel.

![Mattermost sync group memberships](./assets/mattermost-sync-group-memberships.png)

6. Click the **Add Group** button and select your group from the list.
7. Click save.
8. Now in order for the group member to be assigned to that group and channel they will need to sign into Mattermost. If you are the user who is a member of that group you will need to sign out and sign back in.
9. Once you have signed in you should be able to access that channel.

In order to assign groups to teams it is the same process as I just outlined.

## Troubleshooting

### The Keycloak groups list is showing an error

![Mattermost groups error](./assets/mattermost-groups-error.png)

Check the logs for further details and review your Keycloak plugin configs to ensure the Host, Realm, Client ID and Client Secret are correct.

The following logs indicate an issue with your Client ID or Client Secret:
```
{"timestamp":"2025-04-09 14:15:49.465 -04:00","level":"error","msg":"Failed to fetch groups","caller":"app/plugin_api.go:1112","plugin_id":"com.mattermost.plugin-identity-groups-sync","error":"failed to get groups: failed to get auth token: authentication error: failed to authenticate client: 401 Unauthorized: unauthorized_client: Invalid client or Invalid client credentials"}
{"timestamp":"2025-04-09 14:15:49.941 -04:00","level":"error","msg":"Failed to fetch groups count","caller":"app/plugin_api.go:1112","plugin_id":"com.mattermost.plugin-identity-groups-sync","error":"failed to get groups count: failed to get auth token: authentication error: failed to authenticate client: 401 Unauthorized: unauthorized_client: Invalid client or Invalid client credentials"}
```

The following logs indicate a permission issue and your service account may not have the correct role applied:
```
{"timestamp":"2025-04-09 14:22:11.841 -04:00","level":"error","msg":"Failed to fetch groups","caller":"app/plugin_api.go:1112","plugin_id":"com.mattermost.plugin-identity-groups-sync","error":"failed to get groups: operation failed after reauthentication: 403 Forbidden: unknown_error"}
{"timestamp":"2025-04-09 14:22:12.333 -04:00","level":"error","msg":"Failed to fetch groups count","caller":"app/plugin_api.go:1112","plugin_id":"com.mattermost.plugin-identity-groups-sync","error":"failed to get groups count: could not get groups count: 403 Forbidden: unknown_error"}
```

If you applied the incorrect role to your service account user you will need to revoke the service account session in order for your service account to pickup the newly applied role. Remember the correct role is .
In order to revoke a Keycloak session inside Keycloak you would need to have **Use refresh tokens for client credentials grant** enabled.
1. Apply the **realm-admin** to the **mattermost-admin** client.
2. Navigate to **Sessions** in the **mattermost-admin** client.
3. Click the 3 dots on the right and sign out.
![Keycloak revoke session](./assets/keycloak-revoke-session.png)

If you don't see the session inside Keycloak you can destroy the session Mattermost has stored by updating the plugin configs in System Console.

### My SAML user is not being added to his groups inside Mattermost when logging in

The first step is to check the logs for any errors, enabling debug logging in Mattermost will log the assertion info which you can use to check which attributes Mattermost recevied. You can use that to verify the Groups attribute is present in your SAML attributes.

Another option to check your SAML attributes is [this](https://docs.mattermost.com/onboard/sso-saml-technical.html#how-can-i-troubleshoot-the-saml-logon-process).

Ensure the system console **Groups Attribute** value matches up with the attribute assigned in the Keycloak SAML client attributes.
