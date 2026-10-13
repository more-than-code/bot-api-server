package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// QueryChart aggregates samples already held in memory. The Postgres
// implementation does the same aggregation in SQL and does not return raw rows.
func (m *Mem) QueryChart(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time, stepSec int) ([]store.ChartSeries, error) {
	samples, err := m.LoadMetric(ctx, hostID, measurement, from, to)
	if err != nil {
		return nil, err
	}
	series, err := ingest.Bucket(measurement, from, to, stepSec, samples)
	if err != nil {
		return nil, store.ErrUnknownMeasurement
	}
	out := make([]store.ChartSeries, len(series))
	for i, ser := range series {
		points := make([]store.ChartPoint, len(ser.Points))
		for j, p := range ser.Points {
			points[j] = store.ChartPoint{T: p.T, V: p.V}
		}
		out[i] = store.ChartSeries{Name: ser.Name, Unit: ser.Unit, Points: points}
	}
	return out, nil
}

// DeleteOldBatches drops batch ids received before the cutoff.
func (m *Mem) DeleteOldBatches(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, at := range m.batches {
		if at.Before(before) {
			delete(m.batches, key)
		}
	}
	return nil
}
