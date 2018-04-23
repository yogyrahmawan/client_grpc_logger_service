package main

import (
	"context"

	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes"
	"github.com/yogyrahmawan/client_grpc_logger_service/pb"
	glb "github.com/yogyrahmawan/grpcloadbalancing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	loggerServiceClient pb.LoggerServiceClient
)

// JWTAuth hold jwt auth
type JWTAuth struct {
	Token string
}

// GetRequestMetadata gets the current request metadata
func (a *JWTAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"token": a.Token,
	}, nil
}

// RequireTransportSecurity indicates whether the credentials requires transport security
func (a *JWTAuth) RequireTransportSecurity() bool {
	return true
}

func initJWTAuth() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"internal_service": "internal_service",
		"nbf":              time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})
	return token.SignedString([]byte("113070"))
}

func main() {
	// Create the client TLS credentials
	creds, err := credentials.NewClientTLSFromFile("cert/server.crt", "")
	if err != nil {
		log.Fatalf("could not load tls cert: %s", err)
	}

	// initialise jwt auth
	token, err := initJWTAuth()
	if err != nil {
		log.Fatalf("cannot sign jwt, err: %s", err)
	}
	log.Println("Got token " + token)

	auth := JWTAuth{
		Token: token,
	}

	// make generator
	generator := func() (*grpc.ClientConn, error) {
		conn, err := grpc.Dial("localhost:9005", grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(&auth))
		if err != nil {
			log.Fatalf("did not connect: %s", err)
		}
		return conn, err
	}

	end, err := glb.NewEndpoint("localhost:9005", 2, 200, generator)
	if err != nil {
		log.Fatalf("did not connect : %s", err)
	}

	// experiment, make 2 connections
	end2, err := glb.NewEndpoint("localhost:9005", 2, 200, generator)

	lb := glb.NewLoadBalance([]*glb.Endpoint{end, end2})

	http.HandleFunc("/send", func(rw http.ResponseWriter, req *http.Request) {
		// get connection
		nextEnd, err := lb.Get()
		if err != nil {
			log.Fatalf("failed get connection, err : %s", err)
		}
		conn := nextEnd.GetClientConn()
		defer conn.Close()

		loggerServiceClient = pb.NewLoggerServiceClient(conn)

		response, err := loggerServiceClient.SendLog(context.Background(), &pb.LoggerMessage{
			IpPort:      "localhost:8080",
			ServiceName: "test_service",
			Level:       "info",
			Text:        "this is test",
			CreatedAt:   ptypes.TimestampNow(),
		})
		if err != nil {
			log.Errorf("error when calling SendLog: %s", err)
			renderJSON(rw, http.StatusInternalServerError, responseMessage{
				status:  "error",
				message: err.Error(),
			})
			return
		}
		log.Printf("Response from server: %s", response.Status)

		if response.Status != "ok" {
			log.Info("send not ok")
			renderJSON(rw, 422, responseMessage{
				status:  "not_ok",
				message: response.Status,
			})
		}

		log.Debug("seems ok")
		renderJSON(rw, http.StatusOK, responseMessage{
			status:  "ok",
			message: response.Status,
		})

	})

	log.Infof("HTTP server listening on %s", ":6000")
	http.ListenAndServe(":6000", nil)
}
