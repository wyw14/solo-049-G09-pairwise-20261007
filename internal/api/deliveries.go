package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// generateDelivery seals the immutable report for a pass. Repeat POSTs only
// re-verify the sealed artifact and never change pass/recording task state.
func (r *Runtime) generateDelivery(writer http.ResponseWriter, request *http.Request) {
	verification, err := r.Deliveries.Generate(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if verification.Reused {
		status = http.StatusOK
	}
	writeJSON(writer, status, verification)
}

// downloadDelivery returns and verifies the sealed report without rebuilding it.
func (r *Runtime) downloadDelivery(writer http.ResponseWriter, request *http.Request) {
	verification, err := r.Deliveries.Download(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, verification)
}

func (r *Runtime) listDeliveries(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.Deliveries.List()})
}
