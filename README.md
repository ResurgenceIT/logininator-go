# Logininator (Go)

Logininator is a set of tools for creating web application logins. I got tired of creating HTTP endpoints for validating credentials and generating JWT tokens over and over (and over) again, so I decided to make some reusable components. So I did.

![The Destruct-inator Ray](logininator.jpg)

## 🚀 Quick Start

To begin add this to your Go modules. The below commands will retrieve this library, and its dependencies, and add it to your go.mod file.

```bash
go get github.com/app-nerds/logininator-go
go get
```

## Examples

Here are some examples.

### Server Password

Here is an example where you only want to validate a shared secret, or a server password. This example assumes you've got a shared password that is secured somewhere that will be used to validate logins.

```go
// password is some shared secret

logger := logrus.New().WithField("who", "my app")
jwtConfig := identity.JWTServiceConfig{
  AuthSalt:         JWTSalt,
  AuthSecret:       JWTSecret,
  Issuer:           JWTIssuer,
  TimeoutInMinutes: JWTTimeout,
}

config := logininator.NewPasswordOnlyConfig(password, jwtConfig, logger)

// ...HTTP server and mux code goes here. I recommend Gorilla Mux!
router.Handle("/api/login", logininator.LoginHandlerPassword(config)).Methods(http.MethodPost, http.MethodOptions)
```

### User Name & Password

Here is an example where you want to validate a user name and password against some service or database. 

```go
logger := logrus.New().WithField("who", "my app")
jwtConfig := identity.JWTServiceConfig{
  AuthSalt:         JWTSalt,
  AuthSecret:       JWTSecret,
  Issuer:           JWTIssuer,
  TimeoutInMinutes: JWTTimeout,
}

config := logininator.NewUserNamePasswordConfig(jwtConfig, logger)

validateCreds := func(loginRequest logininator.UserNamePasswordRequest) (bool, map[string]interface{}, error) {
  // Here is where you would validate the user name and password provided in
  // in loginReequest. If there is some type of error, be sure to return that.
  // Otherwise, return true in the first result if the credentials pass, or false
  // if they don't. 
  //
  // The second result is any additional information you want to include in the
  // resulting JWT token, like a user ID or permission information.
}

// ...HTTP server and mux code goes here. I recommend Gorilla Mux!
router.Handle("/api/login", logininator.LoginHandlerUserNamePassword(config, validateCreds)).Methods(http.MethodPost, http.MethodOptions)
```

