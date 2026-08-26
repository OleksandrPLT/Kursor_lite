package server

import (
	"net/http"

	kversion "kursor/internal/version"
)

// UpdatesData backs the System Updates page.
type UpdatesData struct {
	PageData
	RunningCommit   string
	Latest          kversion.LatestInfo
	UpdateAvailable bool
	CheckError      string
}

func (s *Server) handleUpdatesPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	data := UpdatesData{
		PageData:      s.basePageData(w, r, "system-updates", sess),
		RunningCommit: kversion.GitCommit,
	}
	latest, err := kversion.CheckLatest()
	if err != nil {
		data.CheckError = err.Error()
	} else {
		data.Latest = latest
		data.UpdateAvailable = kversion.UpdateAvailable(latest)
	}
	s.render(w, "system_updates", data)
}
