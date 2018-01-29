package main

import (
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"time"

	gctx "github.com/gorilla/context"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	dropbox "github.com/tomekwlod/dropbox"
)

var (
	ErrBadRequest           = &Error{"bad_request", 400, "Bad request", "Request body is not well-formed. It must be JSON."}
	ErrNotAcceptable        = &Error{"not_acceptable", 406, "Not Acceptable", "Accept header must be set to 'application/json'."}
	ErrUnsupportedMediaType = &Error{"unsupported_media_type", 415, "Unsupported Media Type", "Content-Type header must be set to: 'application/json'."}
	ErrInternalServer       = &Error{"internal_server_error", 500, "Internal Server Error", "Something went wrong."}
)

// Errors
type Errors struct {
	Errors []*Error `json:"errors"`
}

type Error struct {
	Id     string `json:"id"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func WriteError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(Errors{[]*Error{err}})
}

// Middlewares
func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %+v", err)
				WriteError(w, ErrInternalServer)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %q Request started\n", r.Method, r.URL.String())

		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()

		log.Printf("[%s] %q Request completed after %v\n\n\n", r.Method, r.URL.String(), t2.Sub(t1))
	}

	return http.HandlerFunc(fn)
}

// Here is my request and I would like (to Accept) this response format
// I expect to receive this format only
func acceptHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			WriteError(w, ErrNotAcceptable)
			return
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// Content-Type header tells the server what the attached data actually is
// Only for PUT & POST
func contentTypeHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// if r.Header.Get("Content-Type") != "application/json" {
		// 	WriteError(w, ErrUnsupportedMediaType)
		// 	return
		// }

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func bodyHandler(v interface{}) func(http.Handler) http.Handler {
	t := reflect.TypeOf(v)

	m := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			val := reflect.New(t).Interface()

			err := json.NewDecoder(r.Body).Decode(val)

			if err != nil {
				WriteError(w, ErrBadRequest)
				return
			}

			if next != nil {
				gctx.Set(r, "body", val)
				next.ServeHTTP(w, r)
			}
		}

		return http.HandlerFunc(fn)
	}

	return m
}

// allow CORS
func allowCorsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, PUT")

		w.WriteHeader(200)
	}
}

// Main handlers
func dropboxSearchHandler(w http.ResponseWriter, r *http.Request) {
	params := gctx.Get(r, "params").(httprouter.Params)

	data := dropbox.Search(params.ByName("term"))

	// below or build more complicated function
	var result []map[string]interface{}
	for _, row := range data {
		result = append(result, map[string]interface{}{
			"path": row.Metadata.PathDisplay,
			"size": float32(row.Metadata.Size) / 1024 / 1024,
		})
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(result)
}

func dropboxStorageHandler(w http.ResponseWriter, r *http.Request) {
	result := dropbox.Storage()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(result)
}

// Router
type router struct {
	*httprouter.Router
}

func newRouter() *router {
	return &router{httprouter.New()}
}

func wrapHandler(h http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		gctx.Set(r, "params", ps)

		h.ServeHTTP(w, r)
	}
}

func (r *router) Get(path string, handler http.Handler) {
	r.GET(path, wrapHandler(handler))
}
func (r *router) Post(path string, handler http.Handler) {
	r.POST(path, wrapHandler(handler))
}
func (r *router) Put(path string, handler http.Handler) {
	r.PUT(path, wrapHandler(handler))
}
func (r *router) Delete(path string, handler http.Handler) {
	r.DELETE(path, wrapHandler(handler))
}
func (r *router) Options(path string, handler http.Handler) {
	r.OPTIONS(path, wrapHandler(handler))
}

// type requestSearch struct {
// 	term string `json:"term"`
// }
// type Files struct {
// TimeMS int64                    `json:"timems"`
// Data []map[string]interface{} `json:"data"`
// Data      []model.Trial `json:"data"`
// Paginator Paginator `json:"paginator"`
// }

// type Paginator struct {
// 	Page    int   `json:"page"`
// 	PerPage int   `json:"perpage"`
// 	Total   int64 `json:"total"`
// }

func main() {
	commonHandlers := alice.New(gctx.ClearHandler, loggingHandler, recoverHandler)
	optionsHandlers := alice.New(gctx.ClearHandler, loggingHandler)

	router := newRouter()

	router.Get("/dropbox/search/:term", commonHandlers.Append(contentTypeHandler).ThenFunc(dropboxSearchHandler))
	router.Get("/dropbox/storage", commonHandlers.Append(contentTypeHandler).ThenFunc(dropboxStorageHandler))

	router.Options("/*name", optionsHandlers.ThenFunc(allowCorsHandler))

	port := ":8888"
	log.Printf("Listening on port %s \n\n", port)

	err := http.ListenAndServe(port, router)

	if err != nil {
		panic(err)
	}
}
