package global

import (
	"context"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

func Tracer() trace.Tracer {
	return tracer
}

func StartSpan(ctx context.Context, spanName string) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	return tracer.Start(ctx, spanName)
}

func InitTracer(tracer2 trace.Tracer) {
	if tracer == nil {
		tracer = tracer2
	}
}
