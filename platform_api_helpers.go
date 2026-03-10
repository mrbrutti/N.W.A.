package main

import (
	"net/http"
	"strconv"
	"strings"
)

type platformAPIEngagementContext struct {
	User       platformUserRecord
	Engagement platformEngagementRecord
	View       PlatformEngagementView
	Workspace  *workspace
}

func paginateAPIItems[T any](request *http.Request, items []T) PlatformListResponse[T] {
	paged, pagination := paginateAPISlice(request, items)
	return PlatformListResponse[T]{
		Items:      paged,
		Pagination: pagination,
	}
}

func paginateAPISlice[T any](request *http.Request, items []T) ([]T, PlatformPaginationView) {
	pageSize := apiPageSizeFromRequest(request)
	page := apiPageFromRequest(request)
	total := len(items)
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	if page > totalPages {
		page = totalPages
	}
	startIndex := 0
	if total > 0 {
		startIndex = (page - 1) * pageSize
		if startIndex < 0 {
			startIndex = 0
		}
		if startIndex > total {
			startIndex = total
		}
	}
	endIndex := startIndex + pageSize
	if endIndex > total {
		endIndex = total
	}
	start := 0
	end := 0
	if total > 0 && endIndex >= startIndex {
		start = startIndex + 1
		end = endIndex
	}
	pager := PlatformPaginationView{
		Key:        "api",
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		Start:      start,
		End:        end,
		HasPrev:    page > 1 && total > 0,
		HasNext:    total > 0 && page < totalPages,
	}
	if pager.HasPrev {
		pager.PrevHref = apiPaginationURL(request, page-1, pageSize)
	}
	if pager.HasNext {
		pager.NextHref = apiPaginationURL(request, page+1, pageSize)
	}
	pager.PageSizeHrefs = make([]PlatformPaginationLink, 0, len(platformPaginationSizes))
	for _, size := range platformPaginationSizes {
		pager.PageSizeHrefs = append(pager.PageSizeHrefs, PlatformPaginationLink{
			Label:  strconv.Itoa(size),
			Href:   apiPaginationURL(request, 1, size),
			Active: size == pageSize,
		})
	}
	if total == 0 {
		return items[:0], pager
	}
	return items[startIndex:endIndex], pager
}

func apiPageSizeFromRequest(request *http.Request) int {
	raw := strings.TrimSpace(request.URL.Query().Get("page_size"))
	if raw == "" {
		return platformPaginationSizes[0]
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return platformPaginationSizes[0]
	}
	for _, size := range platformPaginationSizes {
		if value == size {
			return size
		}
	}
	return platformPaginationSizes[0]
}

func apiPageFromRequest(request *http.Request) int {
	raw := strings.TrimSpace(request.URL.Query().Get("page"))
	if raw == "" {
		return 1
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 1
	}
	return value
}

func apiPaginationURL(request *http.Request, page int, pageSize int) string {
	query := request.URL.Query()
	query.Set("page", strconv.Itoa(page))
	query.Set("page_size", strconv.Itoa(pageSize))
	return request.URL.Path + "?" + query.Encode()
}

func (app *application) requireAPIEngagementContext(writer http.ResponseWriter, request *http.Request, withWorkspace bool) (platformAPIEngagementContext, bool) {
	user, _, ok := app.requirePlatformUser(writer, request, false)
	if !ok {
		return platformAPIEngagementContext{}, false
	}

	slug := strings.TrimSpace(request.PathValue("slug"))
	if slug == "" {
		http.NotFound(writer, request)
		return platformAPIEngagementContext{}, false
	}

	engagement, _, err := app.platform.requireEngagement(user, slug)
	if err != nil {
		http.NotFound(writer, request)
		return platformAPIEngagementContext{}, false
	}

	view, err := app.platform.engagementViewByID(user, engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return platformAPIEngagementContext{}, false
	}
	context := platformAPIEngagementContext{
		User:       user,
		Engagement: engagement,
		View:       view,
	}
	if withWorkspace {
		workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return platformAPIEngagementContext{}, false
		}
		context.Workspace = workspace
	}
	return context, true
}
