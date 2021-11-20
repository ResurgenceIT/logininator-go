# Changelog

## v1.1.0

* Added new login method: User name + Password + Code. This provides a way to handle things like multi-tenant systems.
* Added generic JWT middleware to check if an **Authorization** header is present, and the JWT parses correctly. Using this middleware places the JWT token in the context with a key of **jwt**. 

## v1.0.0

* Initial release
