package traces

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type traceContextKey string

const (
	TraceIDKey traceContextKey = "trace.id"
)

func WithTraceID(ctx context.Context) context.Context {
	id, err := uuid.NewRandom()
	if err != nil {
		logrus.Warn(fmt.Errorf("failed to generate trace id: %w", err))
		return ctx
	}
	return context.WithValue(ctx, TraceIDKey, id.String())
}

func Logger(ctx context.Context) *logrus.Entry {
	return logrus.WithField("trace.id", TraceID(ctx))
}

func TraceID(ctx context.Context) string {
	if id, ok := ctx.Value(TraceIDKey).(string); ok {
		return id
	}
	return "<no-trace-id>"
}
