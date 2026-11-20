# Entra Provisioner for Nitrokey

To deploy this, the following is to be done:

1. Host this webpage to `provision.nitrokey.com`
2. Create an Multi-tenant Entra Application. 
3. The application should be SPA (Single Page Application) with callback URL `provision.nitrokey.com`
4. Copy the `client id` and replace it in `index.html`, line 219 and microsoft identity json in `.well-known`
5. For now it is using Nextcloud to store the intermediate responses. Nextcloud usually has CORS policies that blocks the site, so a custom proxy is used. (Line 229 of `index.html`).
6. Also when modifying Line 229 of `index.html`, modify the same on the enroller script as API endpoint.
7. Allow CORS policy from Nextcloud to `provision.nitrokey.com`.
8. For now the enroller script assumes the Nitrokeys have pins set. This is not always the case. TODO: Modify it to make it dynamic.
9. Entra Application would need privacy policy and other documents

## Important

The Entra App needs to be made after publisher verification. https://learn.microsoft.com/en-gb/entra/identity-platform/publisher-verification-overview
