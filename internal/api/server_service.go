package api

import (
	"context"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/freifunkMUC/wg-embed/pkg/wgembed"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type ServerService struct {
	Config *config.AppConfig
	Wg     wgembed.WireGuardInterface
	// DeviceManager is where the networks routed through devices come from.
	// They belong in the client configurations: a client that tunnels only
	// what it is told to would otherwise never send anything to a site
	// behind another device.
	DeviceManager *devices.DeviceManager
	// PasswordChange is whether the server keeps passwords at all - it does
	// when a built-in provider is configured. Whether this session's own
	// password is one of them is decided per request.
	PasswordChange bool
	// TwoFactor is the second factor of the built-in sign-in, nil when the
	// server keeps none.
	TwoFactor *users.TwoFactor
	// Passkeys are the other second factor, nil for the same reason.
	Passkeys *users.Passkeys
}

func passkeyCount(passkeys *users.Passkeys, subject string) int32 {
	if passkeys == nil {
		return 0
	}
	registered, err := passkeys.List(subject)
	if err != nil {
		return 0
	}
	return int32(len(registered))
}

func recoveryCodesLeft(twoFactor *users.TwoFactor, subject string) int32 {
	if twoFactor == nil {
		return 0
	}
	return int32(twoFactor.RecoveryCodesLeft(subject))
}

func (s *ServerService) Info(ctx context.Context, _ *connect.Request[proto.InfoReq]) (*connect.Response[proto.InfoRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	host := s.Config.ExternalHost
	if strings.Contains(host, ":") {
		if !strings.HasPrefix(host, "[") {
			host = "[" + host
		}
		if !strings.HasSuffix(host, "]") {
			host = host + "]"
		}
	}

	publicKey, err := s.Wg.PublicKey()
	if err != nil {
		return nil, internalError(ctx, err, "failed to get public key")
	}

	vpnip, vpnipv6, err := network.ServerVPNIPs(s.Config.VPN.CIDR, s.Config.VPN.CIDRv6)
	if err != nil {
		return nil, internalError(ctx, err, "failed to get server IPs")
	}
	dnsAddress := network.StringJoinIPs(vpnip, vpnipv6)

	return connect.NewResponse(&proto.InfoRes{
		Host:                            stringValue(&host),
		PublicKey:                       publicKey,
		Port:                            int32(s.Config.WireGuard.Port),
		MetadataEnabled:                 s.Config.EnableMetadata,
		InactiveDeviceDeletionEnabled:   s.Config.EnableInactiveDeviceDeletion,
		InactiveDeviceGracePeriod:       durationToDurationpb(&s.Config.InactiveDeviceGracePeriod),
		IsAdmin:                         user.Claims.IsAdmin(),
		AllowedIps:                      s.allowedIPs(),
		DnsEnabled:                      s.Config.DNS.Enabled,
		DnsAddress:                      dnsAddress,
		Filename:                        s.Config.Filename,
		ClientConfigDnsServers:          clientConfigDnsServers(s.Config),
		ClientConfigDnsSearchDomain:     s.Config.ClientConfig.DNSSearchDomain,
		ClientConfigMtu:                 int32(s.Config.ClientConfig.MTU),
		ClientConfigPersistentKeepalive: int32(s.Config.ClientConfig.PersistentKeepalive),
		BuildInfo:                       &proto.BuildInfo{Version: buildinfo.Version(), Commit: buildinfo.ShortCommitHash()},
		Mtu:                             int32(s.Config.WireGuard.MTU),
		ApiTokensEnabled:                s.Config.EnableAPITokens,
		Subject:                         user.Subject,
		PasswordChangeEnabled:           s.PasswordChange && authconfig.HasPassword(user.Provider),
		TwoFactorEnabled:                s.TwoFactor != nil && s.TwoFactor.Enabled(user.Subject),
		RecoveryCodesLeft:               recoveryCodesLeft(s.TwoFactor, user.Subject),
		Passkeys:                        passkeyCount(s.Passkeys, user.Subject),
	}), nil
}

// allowedIPs is what a new client configuration will tunnel: the configured
// networks and whatever is routed through the devices. A configuration that
// was downloaded earlier does not learn about a route added later - the user
// has to fetch it again, or add the network by hand.
func (s *ServerService) allowedIPs() string {
	allowed := append([]string{}, s.Config.VPN.AllowedIPs...)
	if s.DeviceManager != nil {
		for _, routed := range s.DeviceManager.RoutedNetworks() {
			if !slices.Contains(allowed, routed) {
				allowed = append(allowed, routed)
			}
		}
	}
	return strings.Join(allowed, ", ")
}

func clientConfigDnsServers(config *config.AppConfig) string {
	return strings.Join(config.ClientConfig.DNSServers, ", ")
}
