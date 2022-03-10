package logininator

import (
	"context"
	"net/http"
	"strings"

	"github.com/ResurgenceIT/kit/v6/identity"
	"github.com/ResurgenceIT/nerdweb/v2"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func JWTMiddleware(logger *logrus.Entry, jwtConfig identity.JWTServiceConfig) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				err           error
				key           string
				authorization string
				jwt           *jwt.Token
			)

			jwtService := identity.NewJWTService(jwtConfig)
			authorization = r.Header.Get("Authorization")

			if authorization == "" {
				logger.Error("missing authorization header")

				nerdweb.WriteJSON(logger, w, http.StatusBadRequest, GenericError{
					Message: "missing authorization information",
				})

				return
			}

			/*
			 * Get the token from the header
			 */
			auth := strings.SplitN(authorization, " ", 2)

			/*
			 * If we have no "Bearer" portion, this isn't JWT auth
			 */
			if len(auth) != 2 || auth[0] != "Bearer" {
				logger.Error("authorization header is missing 'Bearer' portion")

				nerdweb.WriteJSON(logger, w, http.StatusBadRequest, GenericError{
					Message: "invalid JWT authorization header",
				})

				return
			}

			key = auth[1]

			/*
			 * Validate and parse the token
			 */
			if jwt, err = jwtService.ParseToken(key); err != nil {
				logger.WithError(err).Error("error parsing jwt token")

				nerdweb.WriteJSON(logger, w, http.StatusUnauthorized, GenericError{
					Message: "error parsing authorization",
				})

				return
			}

			ctx := context.WithValue(r.Context(), "jwt", jwt)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JWTMiddlewareHandler(logger *logrus.Entry, jwtConfig identity.JWTServiceConfig, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err           error
			key           string
			authorization string
			jwt           *jwt.Token
		)

		jwtService := identity.NewJWTService(jwtConfig)
		authorization = r.Header.Get("Authorization")

		if authorization == "" {
			logger.Error("missing authorization header")

			nerdweb.WriteJSON(logger, w, http.StatusBadRequest, GenericError{
				Message: "missing authorization information",
			})

			return
		}

		/*
		 * Get the token from the header
		 */
		auth := strings.SplitN(authorization, " ", 2)

		/*
		 * If we have no "Bearer" portion, this isn't JWT auth
		 */
		if len(auth) != 2 || auth[0] != "Bearer" {
			logger.Error("authorization header is missing 'Bearer' portion")

			nerdweb.WriteJSON(logger, w, http.StatusBadRequest, GenericError{
				Message: "invalid JWT authorization header",
			})

			return
		}

		key = auth[1]

		/*
		 * Validate and parse the token
		 */
		if jwt, err = jwtService.ParseToken(key); err != nil {
			logger.WithError(err).Error("error parsing jwt token")

			nerdweb.WriteJSON(logger, w, http.StatusUnauthorized, GenericError{
				Message: "error parsing authorization",
			})

			return
		}

		ctx := context.WithValue(r.Context(), "jwt", jwt)
		handler(w, r.WithContext(ctx))
	}
}
