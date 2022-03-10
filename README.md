# Logininator (Go)

Logininator is a set of tools for creating web application logins. I got tired of creating HTTP endpoints for validating credentials and generating JWT tokens over and over (and over) again, so I decided to make some reusable components. So I did.

![The Destruct-inator Ray](logininator.jpg)

## 🚀 Quick Start

To begin add this to your Go modules. The below commands will retrieve this library, and its dependencies, and add it to your go.mod file.

```bash
go get github.com/ResurgenceIT/logininator-go
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

### User Name, Password, and Code

Here is an example where you want to validate a user name, password, and some type of code (or other identifying piece of information)  against some service or database. 

```go
logger := logrus.New().WithField("who", "my app")
jwtConfig := identity.JWTServiceConfig{
  AuthSalt:         JWTSalt,
  AuthSecret:       JWTSecret,
  Issuer:           JWTIssuer,
  TimeoutInMinutes: JWTTimeout,
}

config := logininator.NewUserNamePasswordCodeConfig(jwtConfig, logger)

validateCreds := func(loginRequest logininator.UserNamePasswordCodeRequest) (bool, map[string]interface{}, error) {
  // Here is where you would validate the user name and password provided in
  // in loginReequest. If there is some type of error, be sure to return that.
  // Otherwise, return true in the first result if the credentials pass, or false
  // if they don't. 
  //
  // The second result is any additional information you want to include in the
  // resulting JWT token, like a user ID or permission information.
}

// ...HTTP server and mux code goes here. I recommend Gorilla Mux!
router.Handle("/api/login", logininator.LoginHandlerUserNamePasswordCode(config, validateCreds)).Methods(http.MethodPost, http.MethodOptions)
```

## Middlewares

### JWT Middleware

When using one of the above JWT-based validators a JWT token is returned. Most often this will be used by front-end clients in each request so your server can validate requests and have additional context when needed. Logininator provides middlewares to make this validation easier. There are two methods provided. **JWTMiddlewareHandler** is for wrapping an individual handler in a JWT middleware (like a GraphQL handler, for example). **JWTMiddleware** is for use with Gorilla Mux to attach to a router (or sub-router).

This example assumes you've setup one of the password validators above, and clients are passing a JWT in the **Authorization** header in the format of ```Bearer <token>```. Here you'll see how to use this middleware to add the JWT token to the HTTP request context.

```go
logger := logrus.New().WithField("who", "my app")
jwtConfig := identity.JWTServiceConfig{
  AuthSalt:         JWTSalt,
  AuthSecret:       JWTSecret,
  Issuer:           JWTIssuer,
  TimeoutInMinutes: JWTTimeout,
}

router.Use(logininator.JWTMiddleware(logger, jwtConfig))
```

### License

Copyright 2022 App Nerds LLC

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

