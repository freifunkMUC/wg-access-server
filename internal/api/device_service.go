package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type DeviceService struct {
	DeviceManager *devices.DeviceManager
}

func (d *DeviceService) AddDevice(ctx context.Context, request *connect.Request[proto.AddDeviceReq]) (*connect.Response[proto.Device], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	device, err := d.DeviceManager.AddDevice(user, req.GetName(), req.GetPublicKey(), req.GetPresharedKey(), req.GetManualIpAssignment(), req.GetManualIpv4Address(), req.GetManualIpv6Address())
	if err != nil {
		return nil, deviceError(ctx, err, "failed to add device")
	}

	audit.Log(ctx, audit.DeviceCreate, logrus.Fields{
		"device":  device.Name,
		"owner":   device.Owner,
		"address": device.Address,
	})

	return connect.NewResponse(mapDevice(device)), nil
}

func (d *DeviceService) ListDevices(ctx context.Context, _ *connect.Request[proto.ListDevicesReq]) (*connect.Response[proto.ListDevicesRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	devices, err := d.DeviceManager.ListDevices(user.Subject)
	if err != nil {
		return nil, internalError(ctx, err, "failed to retrieve devices")
	}
	return connect.NewResponse(&proto.ListDevicesRes{
		Items: mapDevices(devices),
	}), nil
}

func (d *DeviceService) DeleteDevice(ctx context.Context, request *connect.Request[proto.DeleteDeviceReq]) (*connect.Response[emptypb.Empty], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	deviceOwner := user.Subject

	if req.Owner != nil {
		if user.Claims.IsAdmin() {
			deviceOwner = req.Owner.Value
		} else {
			return nil, errNotAdmin()
		}
	}

	if err := d.DeviceManager.DeleteDevice(deviceOwner, req.GetName()); err != nil {
		return nil, deviceError(ctx, err, "failed to delete device")
	}

	audit.Log(ctx, audit.DeviceDelete, logrus.Fields{
		"device": req.GetName(),
		"owner":  deviceOwner,
	})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (d *DeviceService) RenameDevice(ctx context.Context, request *connect.Request[proto.RenameDeviceReq]) (*connect.Response[proto.Device], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	deviceOwner := user.Subject

	if req.Owner != nil {
		if !user.Claims.IsAdmin() {
			return nil, errNotAdmin()
		}
		deviceOwner = req.Owner.Value
	}

	device, err := d.DeviceManager.RenameDevice(deviceOwner, req.GetName(), req.GetNewName())
	if err != nil {
		return nil, deviceError(ctx, err, "failed to rename device")
	}

	audit.Log(ctx, audit.DeviceRename, logrus.Fields{
		"device":   req.GetNewName(),
		"previous": req.GetName(),
		"owner":    deviceOwner,
	})

	return connect.NewResponse(mapDevice(device)), nil
}

// SetDeviceAccess blocks a device from connecting, or gives it an expiry date.
// Admins only, and deliberately so: a user who could lift the block or push
// the expiry date of their own device out would have no block at all. They can
// still delete the device, which takes its access away rather than granting
// any.
func (d *DeviceService) SetDeviceAccess(ctx context.Context, request *connect.Request[proto.SetDeviceAccessReq]) (*connect.Response[proto.Device], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if !user.Claims.IsAdmin() {
		return nil, errNotAdmin()
	}

	deviceOwner := user.Subject
	if req.Owner != nil {
		deviceOwner = req.Owner.Value
	}

	change := devices.AccessChange{ClearExpiresAt: req.GetClearExpiresAt()}
	if req.Disabled != nil {
		disabled := req.Disabled.Value
		change.Disabled = &disabled
	}
	if req.ExpiresAt != nil {
		expiresAt := req.GetExpiresAt().AsTime()
		change.ExpiresAt = &expiresAt
	}

	device, err := d.DeviceManager.SetDeviceAccess(deviceOwner, req.GetName(), change)
	if err != nil {
		return nil, deviceError(ctx, err, "failed to change the access of the device")
	}

	// The state the device is in now, not the change that was asked for: that
	// is what an operator reading the log wants to know. No expiry means no
	// field, as it does for an API token.
	fields := logrus.Fields{
		"device":   device.Name,
		"owner":    device.Owner,
		"disabled": device.Disabled,
	}
	if device.ExpiresAt != nil {
		fields["expires_at"] = device.ExpiresAt
	}
	audit.Log(ctx, audit.DeviceAccess, fields)

	return connect.NewResponse(mapDevice(device)), nil
}

// SetDeviceRoutes sets the networks that live behind a device. Admins only,
// like SetDeviceAccess: the routes decide where everybody's traffic for those
// networks goes, so they are not the device owner's to choose.
func (d *DeviceService) SetDeviceRoutes(ctx context.Context, request *connect.Request[proto.SetDeviceRoutesReq]) (*connect.Response[proto.Device], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if !user.Claims.IsAdmin() {
		return nil, errNotAdmin()
	}

	deviceOwner := user.Subject
	if req.Owner != nil {
		deviceOwner = req.Owner.Value
	}

	device, err := d.DeviceManager.SetDeviceRoutes(deviceOwner, req.GetName(), req.GetRoutes())
	if err != nil {
		return nil, deviceError(ctx, err, "failed to change the routes of the device")
	}

	audit.Log(ctx, audit.DeviceRoutes, logrus.Fields{
		"device": device.Name,
		"owner":  device.Owner,
		"routes": device.Routes,
	})

	return connect.NewResponse(mapDevice(device)), nil
}

func (d *DeviceService) ListAllDevices(ctx context.Context, _ *connect.Request[proto.ListAllDevicesReq]) (*connect.Response[proto.ListAllDevicesRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if !user.Claims.IsAdmin() {
		return nil, errNotAdmin()
	}

	devices, err := d.DeviceManager.ListAllDevices()
	if err != nil {
		return nil, internalError(ctx, err, "failed to retrieve devices")
	}

	return connect.NewResponse(&proto.ListAllDevicesRes{
		Items: mapDevices(devices),
	}), nil
}

// deviceError turns err into the error the client gets. Only a validation
// error carries its message to the client: anything else can hold storage or
// schema details ("UNIQUE constraint failed: devices.public_key"), which the
// client has no use for and should not learn.
func deviceError(ctx context.Context, err error, fallback string) error {
	var validation *devices.ValidationError
	if errors.As(err, &validation) {
		return connect.NewError(connect.CodeInvalidArgument, validation)
	}
	return internalError(ctx, err, fallback)
}

func mapDevice(d *storage.Device) *proto.Device {
	return &proto.Device{
		Name:              d.Name,
		Owner:             d.Owner,
		OwnerName:         d.OwnerName,
		OwnerEmail:        d.OwnerEmail,
		OwnerProvider:     d.OwnerProvider,
		PublicKey:         d.PublicKey,
		PresharedKey:      d.PresharedKey,
		Address:           d.Address,
		CreatedAt:         timeToTimestamp(&d.CreatedAt),
		LastHandshakeTime: timeToTimestamp(d.LastHandshakeTime),
		ReceiveBytes:      d.ReceiveBytes,
		TransmitBytes:     d.TransmitBytes,
		Endpoint:          d.Endpoint,
		Disabled:          d.Disabled,
		ExpiresAt:         timeToTimestamp(d.ExpiresAt),
		Routes:            d.RouteList(),
		/**
		 * WireGuard is a connectionless UDP protocol - data is only
		 * sent over the wire when the client is sending real traffic.
		 * WireGuard has no keep alive packets by default to remain as
		 * silent as possible.
		 *
		 */
		Connected: d.LastHandshakeTime != nil && devices.IsConnected(*d.LastHandshakeTime),
	}
}

func mapDevices(devices []*storage.Device) []*proto.Device {
	items := []*proto.Device{}
	for _, d := range devices {
		items = append(items, mapDevice(d))
	}
	return items
}
