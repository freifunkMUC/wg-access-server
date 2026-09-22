package services

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	"github.com/freifunkMUC/wg-embed/pkg/wgembed"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/network"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type ServerService struct {
	Config *config.AppConfig
	Wg     wgembed.WireGuardInterface
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

	var hostVPNIP string
	if vpnip.IsValid() {
		hostVPNIP = vpnip.Addr().String()
	} else {
		hostVPNIP = ""
	}

	return connect.NewResponse(&proto.InfoRes{
		Host:      stringValue(&host),
		PublicKey: publicKey,
		Port:      int32(s.Config.WireGuard.Port),
		// TODO IPv6 what is HostVpnIp used for, do we need HostVpnIpv6 as well?
		HostVpnIp:                       hostVPNIP,
		MetadataEnabled:                 s.Config.EnableMetadata,
		InactiveDeviceDeletionEnabled:   s.Config.EnableInactiveDeviceDeletion,
		InactiveDeviceGracePeriod:       DurationToDurationpb(&s.Config.InactiveDeviceGracePeriod),
		IsAdmin:                         user.Claims.IsAdmin(),
		AllowedIps:                      allowedIPs(s.Config),
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
	}), nil
}

func allowedIPs(config *config.AppConfig) string {
	return strings.Join(config.VPN.AllowedIPs, ", ")
}

func clientConfigDnsServers(config *config.AppConfig) string {
	return strings.Join(config.ClientConfig.DNSServers, ", ")
}
