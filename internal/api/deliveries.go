package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func (r *Runtime) generateDelivery(writer http.ResponseWriter, request *http.Request) {
	report, created, err := r.Deliveries.Generate(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(writer, status, map[string]any{"report": report, "created": created})
}

// downloadDelivery only verifies the immutable report; it never mutates pass state.
func (r *Runtime) downloadDelivery(writer http.ResponseWriter, request *http.Request) {
	var revision int64
	if raw := request.URL.Query().Get("revision"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			writeError(writer, fmt.Errorf("revision must be a positive integer"))
			return
		}
		revision = parsed
	}
	report, verified, err := r.Deliveries.Download(chi.URLParam(request, "passID"), revision)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"report": report, "verified": verified, "checksum": report.Checksum})
}

func (r *Runtime) listDeliveries(writer http.ResponseWriter, request *http.Request) {
	summaries, err := r.Deliveries.List(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": summaries})
}
