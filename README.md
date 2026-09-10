# fleet-bridge

Lets a WordPress plugin accept commands from **Fleet**, verified.

Fleet is a WP Media application where an agency manages a plugin across every
site on its licence from one dashboard. To act on a site it signs a short-lived
token, because it deliberately holds no customer credential — this package is
what a plugin uses to check one.

The implementation is under review in the first pull request against this
branch. See wp-media/fleet#6 for the wider piece of work, and wp-media/fleet#55
for why this is a shared package rather than code copied into each plugin.
