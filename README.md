# Identity Groups Sync Mattermost Plugin

This plugin synchronizes user groups from Keycloak to Mattermost.

## License

This repository is licensed under the [Mattermost Source Available License](LICENSE) and requires a valid Enterprise Edition License when used for production. See [frequently asked questions](https://docs.mattermost.com/overview/faq.html#mattermost-source-available-license) to learn more.

Although a valid Mattermost Enterprise Edition License is required if using this plugin in production, the [Mattermost Source Available License](LICENSE) allows you to compile and test this plugin in development and testing environments without a Mattermost Enterprise Edition License. As such, we welcome community contributions to this plugin.

If you're running an Enterprise Edition of Mattermost and don't already have a valid license, you can obtain a trial license from **System Console > Edition and License**. If you're running the Team Edition of Mattermost, including when you run the server directly from source, you may instead configure your server to enable both testing (`ServiceSettings.EnableTesting`) and developer mode (`ServiceSettings.EnableDeveloper`). These settings are not recommended in production environments.

## Features

- Sync Keycloak groups or roles with Mattermost groups.
- Configurable mapping type: use Keycloak groups or roles as the source for Mattermost groups.
- Sync groups with teams or channels.
- Assign Mattermost group memberships to users on sign in through SAML based on the group or role memberships in their SAML assertion.

## Requirements

- Mattermost Server v10.9 or higher.
- A valid Mattermost Enterprise Edition license.

## Development guide

1. Run Keycloak locally with Mattermost by adding it to your `ENABLED_DOCKER_SERVICES`, see our SAML setup guide [here](https://github.com/mattermost/mattermost/blob/master/server/build/docker/keycloak/README.md).
2. Follow our plugin setup guide [./docs/INSTALL.md](./docs/INSTALL.md).

## Installation

Check out our guide in [./docs/INSTALL.md](./docs/INSTALL.md).

## FAQ

### What is a group synced channel or team?

In the installation documentation we walked through setting up your first synchronization which covers it at a high level. There is more information about Group sync with LDAP in Mattermost [here](https://docs.mattermost.com/onboard/ad-ldap-groups-synchronization.html). Those docs apply to LDAP but this plugin uses all the same synchronization features as LDAP groups.

### I linked a group, synced it to a channel but the Keycloak group members were not automatically added to the channel?

If you newly link a Keycloak group to Mattermost that has not been linked before, group members will need sign out and sign back in to be added to the group, channels and teams. This is because we only sync a user's group memberships with existing Mattermost groups on login. If a group is already synced to Mattermost and you add/remove the group from a channel, user's channel membership will automatically update.

### In which cases will a user's channel and team membership automatically update without requiring the user to sign out and sign back in?

If a user is logged in and is currently a member of Group123, and you assign Group123 to a channel or team, then the user will automatically get added to the channel or team without requiring a logout. The same rule applies if you unassign Group123 from a **group_synced** team or channel.

### I'm unable to add a group to a channel of a group synced team?

If a team is group synced and you want to group sync a channel within the team, the group assigned to the channel must also be synced to the team.

### I'm still a member of a team that is not group synced but it is associated to a group that I was previsouly a member of?

Groups can become associated with teams when a group is linked to a channel within that team. When a user is removed from a group, the system cannot distinguish whether they were originally added to the team directly or through the group association. If the team is not group-constrained, users will
remain members of the team even after being removed from the associated group, but they will be removed from any group-synced channels. If you want users to be automatically removed from the team when they're removed from the associated group, you should configure the team as **group constrained**.

### Can regular end users see these groups in Mattermost?

These groups will not be visible to end users within Mattermost unless you enable group mentions for that particular group. Enabling group mentions allows users to @ mention groups in posts and allows them to see the current group members. Group mentions are disabled by default for each group.

## Configuration Options

### Keycloak Mapping Type

The plugin supports two mapping types that determine how Keycloak entities are synchronized with Mattermost groups:

#### Groups Mapping (Default)
- Uses Keycloak groups as the source for Mattermost groups
- Requires service account to have access to view Keycloak groups
- SAML assertion should contain group names in the configured groups attribute

#### Roles Mapping  
- Uses Keycloak realm roles as the source for Mattermost groups
- Requires service account to have the `view-realm` role to access Keycloak realm roles
- SAML assertion should contain role names in the configured groups attribute
- Useful when your organization uses roles instead of groups for access control

## Keycloak limitations 

### Keycloak group/role names in SAML assertion

The SAML assertion for group or role memberships contains the name of the group/role, not the ID.  

![Groups attribute](./docs/assets/saml-groups-attribute.png)

This is a limitation in Keycloak, they do not support passing an ID as an attribute value. In Mattermost we reference the Keycloak group or role by storing the Keycloak ID in the UserGroups table, not by storing the name. This is because the Keycloak ID is immutable but groups/roles can be renamed. 

When the user logs in we have a list of Keycloak group/role names from the SAML assertion, our UserGroups table contains the ID. To match up SAML assertion groups/roles to the Mattermost groups we keep a map of your Keycloak groups or roles where the key is the Keycloak group/role name, and the value is the Keycloak group/role ID. This map is updated every hour by a job that runs in the background. If a user logs in with a new group/role before this job picks it up, we reach out to the keycloak server and pull in the group or role information. The map saves us having to reach out to keycloak for each individual group/role that is in the SAML assertion. 

The only limitation with keeping this map is that if 2 groups (or 2 roles) swap names with each other and someone logs in before the background job runs, they will end up in the wrong groups. While this is an edge case that is unlikely to happen, you should be aware. 

### Group memberships from Keycloak are only synced on login

This was the requirements when creating the plugin. The code can be easily updated to include a job in order to sync these on a schedule.

#### Keycloak sub groups

We do not support Keycloak sub groups at this time.
