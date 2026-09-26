package api

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The API leaves out what a device does not have - a device that never
// connected has no last handshake - so these keep nil as nil.

func timeToTimestamp(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timestamppb.New(*value)
}

func durationToDurationpb(value *time.Duration) *durationpb.Duration {
	if value == nil {
		return nil
	}
	return durationpb.New(*value)
}

func stringValue(value *string) *wrapperspb.StringValue {
	if value == nil {
		return nil
	}
	return &wrapperspb.StringValue{Value: *value}
}
