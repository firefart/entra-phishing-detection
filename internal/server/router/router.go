package router

import (
	"errors"
	"net/http"
	"slices"

	"github.com/firefart/entra-phishing-detection/internal/server/httperror"
)

type HandlerFunc func(http.ResponseWriter, *http.Request) error

type Router struct {
	globalChain  []func(http.Handler) http.Handler
	routeChain   []func(http.Handler) http.Handler
	isSubRouter  bool
	mux          *http.ServeMux
	errorHandler func(http.ResponseWriter, *http.Request, error)
}

func New() *Router {
	return &Router{
		mux:          http.NewServeMux(),
		errorHandler: defaultErrorHandler,
	}
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	var httpErr *httperror.HTTPError
	if errors.As(err, &httpErr) {
		http.Error(w, err.Error(), httpErr.StatusCode)
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Router) SetErrorHandler(fn func(http.ResponseWriter, *http.Request, error)) {
	r.errorHandler = fn
}

func (r *Router) Use(mw ...func(http.Handler) http.Handler) {
	if r.isSubRouter {
		r.routeChain = append(r.routeChain, mw...)
	} else {
		r.globalChain = append(r.globalChain, mw...)
	}
}

func (r *Router) Group(fn func(r *Router)) {
	subRouter := &Router{routeChain: slices.Clone(r.routeChain), isSubRouter: true, mux: r.mux}
	fn(subRouter)
}

func (r *Router) wrapHandlerFunc(h HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := h(w, req); err != nil {
			r.errorHandler(w, req, err)
		}
	})
}

func (r *Router) HandleFunc(pattern string, h HandlerFunc) {
	r.Handle(pattern, r.wrapHandlerFunc(h))
}

func (r *Router) Handle(pattern string, h http.Handler) {
	for _, mw := range slices.Backward(r.routeChain) {
		h = mw(h)
	}
	r.mux.Handle(pattern, h)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, rq *http.Request) {
	var h http.Handler = r.mux

	for _, mw := range slices.Backward(r.globalChain) {
		h = mw(h)
	}
	h.ServeHTTP(w, rq)
}
