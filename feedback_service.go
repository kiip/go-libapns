//Package for creating a connection to Apple's APNS gateway and facilitating
//sending push notifications via that gateway
package apns

import (
	"container/list"
	//"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/kiip/openssl"
	"io"
	"net"
	"time"
)

//Config for creating an APNS Feedback Service Connection
type APNSFeedbackServiceConfig struct {
	//bytes for cert.pem : required
	CertificateBytes []byte
	//bytes for key.pem : required
	KeyBytes []byte
	//apple gateway, defaults to "feedback.push.apple.com"
	GatewayHost string
	//apple gateway port, defaults to "2196"
	GatewayPort string
	//number of seconds to wait for connection before bailing, defaults to 5 seconds
	SocketTimeout int
	//number of seconds to wait for Tls handshake to complete before bailing, defaults to 5 seconds
	TlsTimeout int
}

//Feedback Response
type FeedbackResponse struct {
	//A timestamp indicating when APNs
	//determined that the app no longer exists on the device.
	//This value represents the seconds since 12:00 midnight on January 1, 1970 UTC.
	Timestamp uint32
	//Device push token
	Token string
}

const (
	//Size of feedback header frame
	FEEDBACK_RESPONSE_HEADER_FRAME_SIZE = 6
)

//Create a new apns feedback service connection with supplied config
//If invalid config an error will be returned
//Also if unable to create a connection an error will be returned
//Will return a list of *FeedbackResponse or error
func ConnectToFeedbackService(config *APNSFeedbackServiceConfig) (*list.List, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}

	certificate, err := openssl.LoadCertificateFromPEM(config.CertificateBytes)
	if err != nil {
		return nil, err
	}
	if err := ctx.UseCertificate(certificate); err != nil {
		return nil, err
	}

	privateKey, err := openssl.LoadPrivateKeyFromPEM(config.KeyBytes)
	if err != nil {
		return nil, err
	}
	if err := ctx.UsePrivateKey(privateKey); err != nil {
		return nil, err
	}

	if config.GatewayPort == "" {
		config.GatewayPort = "2196"
	}
	if config.GatewayHost == "" {
		config.GatewayHost = "feedback.push.apple.com"
	}
	if config.SocketTimeout == 0 {
		config.SocketTimeout = 5
	}
	if config.TlsTimeout == 0 {
		config.TlsTimeout = 5
	}

	socket, err := net.DialTimeout("tcp",
		config.GatewayHost+":"+config.GatewayPort,
		time.Duration(config.SocketTimeout)*time.Second)
	if err != nil {
		//failed to connect to gateway
		return nil, err
	}

	sslSocket, err := openssl.Client(socket, ctx)
	if err != nil {
		return nil, err
	}

	sslSocket.SetDeadline(time.Now().Add(time.Duration(config.TlsTimeout) * time.Second))
	if err := sslSocket.Handshake(); err != nil {
		return nil, err
	}
	sslSocket.SetDeadline(time.Time{})

	//hooray! we're connected

	//let socket close itself when we're finished
	defer sslSocket.Close()

	return readFromFeedbackService(sslSocket)
}

//Read from the socket until there is no more to be read or an error occurs
//Then close the socket
//On error some responses may be returned so one should check that the list
//returned doesn't have anything in it
func readFromFeedbackService(socket net.Conn) (*list.List, error) {

	headerBuffer := make([]byte, FEEDBACK_RESPONSE_HEADER_FRAME_SIZE)
	responses := list.New()

	for {
		bytesRead, err := socket.Read(headerBuffer)
		if err != nil {
			if err == io.EOF {
				//we're good, just reached the end of the socket
				return responses, nil
			} else {
				//this is a legit error, return it
				return responses, err
			}
		}

		if bytesRead != FEEDBACK_RESPONSE_HEADER_FRAME_SIZE {
			//? should always be this size...
			return responses,
				errors.New(fmt.Sprintf("Should have read %v header bytes but read %v bytes",
					FEEDBACK_RESPONSE_HEADER_FRAME_SIZE, bytesRead))
		}

		tokenSize := int(binary.BigEndian.Uint16(headerBuffer[4:6]))

		tokenBuffer := make([]byte, tokenSize)

		bytesRead, err = socket.Read(tokenBuffer)
		if err != nil {
			if err == io.EOF {
				//we're good, just reached the end of the socket
				return responses, nil
			} else {
				//this is a legit error, return it
				return responses, err
			}
		}

		if bytesRead != tokenSize {
			//? should always be this size...
			return responses,
				errors.New(fmt.Sprintf("Should have read %v token bytes but read %v bytes",
					tokenSize, bytesRead))
		}

		response := new(FeedbackResponse)
		response.Timestamp = binary.BigEndian.Uint32(headerBuffer[0:4])
		response.Token = hex.EncodeToString(tokenBuffer)
		responses.PushBack(response)
	}

	return responses, nil
}
