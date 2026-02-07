package config

import (
	"errors"
	"regexp"

	"github.com/vishvananda/netlink"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type Config struct {
	LogLevel LogLevel `name:"log-level" description:"Logging level for the application. One of debug, info, warn, or error" default:"info"`
	HBRP     HBRP     `name:"hbrp" description:"Configuration for the HBRP client"`
	IPSC     IPSC     `name:"ipsc" description:"Configuration for the IPSC server"`
}

// IPSC creates a virtual network interface and listens for IPSC packets on it.
type IPSC struct {
	Interface  string   `name:"interface" description:"Interface to listen for IPSC packets on"`
	Port       uint16   `name:"port" description:"Port to listen for IPSC packets on"`
	IP         string   `name:"ip" description:"IP address to listen for IPSC packets on" default:"10.10.250.1"`
	SubnetMask int      `name:"subnet-mask" description:"Subnet mask for the virtual network interface created for IPSC packets" default:"24"`
	Auth       IPSCAuth `name:"auth" description:"Authentication configuration for the IPSC server"`
}

type IPSCAuth struct {
	Enabled bool   `name:"enabled" description:"Whether to require authentication for IPSC clients"`
	Key     string `name:"key" description:"Authentication key for IPSC clients. Required if auth is enabled"`
}

type HBRP struct {
	Callsign string `name:"callsign" description:"Callsign to use for the HBRP connection"`
	ID       uint32 `name:"radio-id" description:"Radio ID for the HBRP connection"`
	// RXFreq is in Hz
	RXFreq uint `name:"rx-freq" description:"Receive frequency in Hz for the HBRP connection"`
	// TXFreq is in Hz
	TXFreq uint `name:"tx-freq" description:"Transmit frequency in Hz for the HBRP connection"`
	// TXPower is in dBm
	TXPower uint8 `name:"tx-power" description:"Transmit power in dBm for the HBRP connection"`
	// ColorCode is the DMR color code
	ColorCode uint8 `name:"color-code" description:"DMR color code for the HBRP connection"`
	// Latitude with north as positive [-90,+90]
	Latitude float64 `name:"latitude" description:"Latitude with north as positive [-90,+90] for the HBRP connection"`
	// Longitude with east as positive [-180+,180]
	Longitude float64 `name:"longitude" description:"Longitude with east as positive [-180+,180] for the HBRP connection"`
	// Height in meters
	Height       uint16 `name:"height" description:"Height in meters for the HBRP connection"`
	Location     string `name:"location" description:"Location for the HBRP connection"`
	Description  string `name:"description" description:"Description for the HBRP connection"`
	URL          string `name:"url" description:"URL for the HBRP connection"`
	MasterServer string `name:"master-server" description:"Master server for the HBRP connection"`
	Password     string `name:"password" description:"Password for the HBRP connection"`
}

var (
	ErrInvalidLogLevel         = errors.New("invalid log level provided")
	ErrInvalidHBRPCallsign     = errors.New("invalid HBRP callsign provided")
	ErrInvalidHBRPColorCode    = errors.New("invalid HBRP color code provided")
	ErrInvalidHBRPLongitude    = errors.New("invalid HBRP longitude provided")
	ErrInvalidHBRPLatitude     = errors.New("invalid HBRP latitude provided")
	ErrInvalidHBRPMasterServer = errors.New("invalid HBRP master server provided")
	ErrInvalidHBRPPassword     = errors.New("invalid HBRP password provided")
	ErrInvalidIPSCInterface    = errors.New("invalid IPSC interface provided")
	ErrInvalidIPSCIP           = errors.New("invalid IPSC IP address provided")
	ErrInvalidIPSCSubnetMask   = errors.New("invalid IPSC subnet mask provided")
	ErrInvalidIPSCAuthKey      = errors.New("invalid IPSC authentication key provided")
)

func (c Config) Validate() error {
	switch c.LogLevel {
	case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
	default:
		return ErrInvalidLogLevel
	}

	if c.HBRP.Callsign == "" {
		return ErrInvalidHBRPCallsign
	}

	if c.HBRP.ColorCode > 15 {
		return ErrInvalidHBRPColorCode
	}

	if c.HBRP.Longitude < -180 || c.HBRP.Longitude > 180 {
		return ErrInvalidHBRPLongitude
	}

	if c.HBRP.Latitude < -90 || c.HBRP.Latitude > 90 {
		return ErrInvalidHBRPLatitude
	}

	if c.HBRP.MasterServer == "" {
		return ErrInvalidHBRPMasterServer
	}

	if c.HBRP.Password == "" {
		return ErrInvalidHBRPPassword
	}

	if c.IPSC.Interface == "" {
		return ErrInvalidIPSCInterface
	}

	_, err := netlink.LinkByName(c.IPSC.Interface)
	if err != nil {
		return ErrInvalidIPSCInterface
	}

	if c.IPSC.IP == "" {
		return ErrInvalidIPSCIP
	}

	if c.IPSC.SubnetMask < 1 || c.IPSC.SubnetMask > 32 {
		return ErrInvalidIPSCSubnetMask
	}

	if c.IPSC.Auth.Enabled && c.IPSC.Auth.Key == "" {
		return ErrInvalidIPSCAuthKey
	}

	// Check authkey is [0-9a-fA-F]{0,40} if c.IPSC.Auth.Enabled {
	regexp := regexp.MustCompile(`^[0-9a-fA-F]{0,40}$`)
	if !regexp.MatchString(c.IPSC.Auth.Key) {
		return ErrInvalidIPSCAuthKey
	}

	return nil
}
