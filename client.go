package rest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	Post  = http.MethodPost  // "POST"
	Put   = http.MethodPut   // "PUT"
	Patch = http.MethodPatch // "PATCH"
	Get   = http.MethodGet   // "GET"
)

var (
	ErrURLNotExist          = errors.New("url not exist")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrForbidden            = errors.New("forbidden")
	ErrInternalServer       = errors.New("internal server error")
	ErrPrecondition         = errors.New("precondition failed")
	ErrPreconditionRequired = errors.New("precondition required")
	ErrBadRequest           = errors.New("bad request")
	errHTTPCode             = errors.New("undefined status code")
	errHTTPFlagNotEmpty     = errors.New("flag not empty")
	errRefreshTokenFail     = errors.New("refresh token failed")
	errGetTokenFail         = errors.New("get token failed")
	errSendFail             = errors.New("request data failed")
)

type User map[string]interface{}

/*
Auth defines information for authentication, includes Account, Password,
and the Token which gets from rest server.
*/
type Auth struct {
	Account    User
	LoginURL   string
	RefreshURL string
	Token      string
	Expire     int64
}

/*
HTTPReq defines information for http request, includes Method, BaseURL,
Path, Body and User.
*/
type HTTPReq struct {
	client  *http.Client
	baseURL string
	User    Auth
}

type tokenData struct {
	Flag   string    `json:"error"`
	Token  string    `json:"token"`
	Expire time.Time `json:"expire"`
}

// NewHTTPReq creates a new HTTPReq instance with a given base URL, user information,
// timeout settings, and a flag to disable keep-alive connections.
func NewHTTPReq(baseURL string, user Auth, timeout int, disableKeepAlive bool) *HTTPReq {
	return &HTTPReq{
		client:  newClient(timeout, disableKeepAlive),
		baseURL: baseURL,
		User:    user,
	}
}

/*
GetToken gets the token from rest server
Return:
  - Running error of the function call
*/
func (r *HTTPReq) GetToken() error {
	data, _ := json.Marshal(r.User.Account)
	tokenRaw, err := r.post(r.User.LoginURL, data, nil)
	if err != nil {
		return fmt.Errorf("%w, %v", errGetTokenFail, err)
	}

	if err = r.parseToken(tokenRaw); err != nil {
		return fmt.Errorf("%w, %v", errGetTokenFail, err)
	}

	return err
}

/*
RefreshToken refreshes the token from rest server
Return:
  - Running error of the function call
*/
func (r *HTTPReq) RefreshToken() error {
	tokenRaw, err := r.get(r.User.RefreshURL, nil)
	if err != nil {
		return fmt.Errorf("%w, %v", errRefreshTokenFail, err)
	}

	if err = r.parseToken(tokenRaw); err != nil {
		return fmt.Errorf("%w, %v", errRefreshTokenFail, err)
	}

	return nil
}

func (r *HTTPReq) parseToken(raw []byte) error {
	const buffer = -10

	t := new(tokenData)

	if err := json.Unmarshal(raw, t); err != nil {
		return fmt.Errorf("%w", err)
	}

	if t.Flag != "" {
		return fmt.Errorf("%w, flag: %s", errHTTPFlagNotEmpty, t.Flag)
	}

	r.User.Token = t.Token
	r.User.Expire = t.Expire.Add(buffer * time.Minute).Unix()

	return nil
}

/*
request sends the request to rest server
Parameter:

	vs - Query parameter

Return:
  - Response body
  - Running error of the function call
*/
func (r *HTTPReq) request(method, path string, data []byte,
	headers map[string]string,
	vs ...map[string]string) ([]byte, error) {
	return r.requestWithContext(context.Background(), method, path, data, headers, vs...)
}

func (r *HTTPReq) requestWithContext(
	ctx context.Context, method, path string, data []byte,
	headers map[string]string,
	vs ...map[string]string) ([]byte, error) {

	finalURL := fmt.Sprintf("%s%s", r.baseURL, path)

	req, err := newRequest(ctx, finalURL, method, data, headers, vs...)
	if err != nil {
		return nil, fmt.Errorf("%w, body: %s", err, data)
	}

	if r.User.Token != "" { // Handle token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.User.Token))
	} else if r.User.Account != nil { // Handle basic auth
		user, existed := r.User.Account["username"]
		if !existed {
			user, existed = r.User.Account["name"]
		}

		if !existed {
			user = r.User.Account["user"]
		}

		pwd := r.User.Account["password"]

		name, uok := user.(string)
		if !uok {
			return nil, fmt.Errorf("%w, user: %v", errHTTPCode, user)
		}

		passwd, pok := pwd.(string)
		if !pok {
			return nil, fmt.Errorf("%w, pwd: %v", errHTTPCode, pwd)
		}

		req.SetBasicAuth(name, passwd)
	}

	return doRequest(req, r.client)
}

func newRequest(ctx context.Context, url, method string, data []byte,
	headers map[string]string,
	vs ...map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("new reques, %w", err)
	}

	if len(vs) == 1 && len(vs[0]) != 0 { // Handle query parameter
		q := req.URL.Query()

		for k, v := range vs[0] {
			q.Add(k, v)
		}

		req.URL.RawQuery = q.Encode()
	}

	// Add headers
	req.Header.Add("Content-Type", "application/json")

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

func newClient(timeout int, onceRequest bool) *http.Client {
	const idletime, idleconns = 30, 9

	tr := &http.Transport{
		DisableKeepAlives:   onceRequest,
		IdleConnTimeout:     idletime * time.Second,
		MaxIdleConnsPerHost: idleconns,
		MaxConnsPerHost:     idleconns,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}
}

func doRequest(req *http.Request, client *http.Client) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request error: %w", err)
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPreconditionFailed:
		return nil, fmt.Errorf("%w, code: %v", ErrPrecondition, resp.StatusCode)
	case http.StatusPreconditionRequired:
		return nil, fmt.Errorf("%w, code: %v", ErrPreconditionRequired, resp.StatusCode)
	case http.StatusBadRequest:
		return nil, fmt.Errorf("%w, code: %v", ErrBadRequest, resp.StatusCode)
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w, code: %v", ErrURLNotExist, resp.StatusCode)
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%w, code: %v", ErrUnauthorized, resp.StatusCode)
	case http.StatusForbidden:
		return nil, fmt.Errorf("%w, code: %v", ErrForbidden, resp.StatusCode)
	case http.StatusInternalServerError:
		return nil, fmt.Errorf("%w, code: %v", ErrInternalServer, resp.StatusCode)
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("%w, code: %v", errHTTPCode, resp.StatusCode)
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzipReader, gerr := gzip.NewReader(resp.Body)
		if gerr != nil {
			return nil, fmt.Errorf("gzip reader error: %w", gerr)
		}

		reader = gzipReader
		defer reader.Close()
	default:
		reader = resp.Body
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return body, fmt.Errorf("response read body, %w", err)
		}

		return nil, fmt.Errorf("%w", err)
	}

	return body, nil
}

/*
GetData gets the sends the request to get data
from rest server
Parameter:

	reqPath - request path for rest server

Return:
  - Response body
  - Running error of the function call
*/
func (r *HTTPReq) GetData(reqPath string) ([]byte, error) {
	return r.GetDataWithHeader(reqPath, nil)
}

func (r *HTTPReq) GetDataWithHeader(reqPath string, headers map[string]string) ([]byte, error) {
	if err := r.checkToken(); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	str, err := r.get(reqPath, headers)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return str, nil
}

func (r *HTTPReq) checkToken() error {
	if r.User.LoginURL == "" {
		return nil
	}

	if r.User.Expire > time.Now().Unix() {
		return nil
	}

	if err := r.RefreshToken(); err == nil {
		return nil
	}

	r.User.Token = "" // token expired
	if err := r.GetToken(); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

/*
SetData sends a POST request to the server with the given data and
returns the response body. If the request fails, it will return an
error.

The request will automatically refresh the token if it is expired.

Parameter:

	path - The path to send the request to
	data - The data to send in the request body

Return:

	- The response body
	- An error if the request fails
*/
func (r *HTTPReq) SetData(path string, data []byte) ([]byte, error) {
	return r.SetDataWithHeaders(path, data, nil)
}

/*
SetDataWithHeaders sends a POST request to the server with the given data and
returns the response body. If the request fails, it will return an
error.

The request will automatically refresh the token if it is expired.

Parameter:

	path - The path to send the request to
	data - The data to send in the request body
	headers - The headers to send with the request

Return:

	- The response body
	- An error if the request fails
*/
func (r *HTTPReq) SetDataWithHeaders(path string, data []byte, headers map[string]string) ([]byte, error) {
	if err := r.checkToken(); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return r.post(path, data, headers)
}

/*
UpdateData sends a PUT request to the server with the given data and
returns the response body. If the request fails, it will return an
error.

The request will automatically refresh the token if it is expired.

Parameter:

	path - The path to send the request to
	data - The data to send in the request body

Return:

	- The response body
	- An error if the request fails
*/
func (r *HTTPReq) UpdateData(path string, data []byte) ([]byte, error) {
	return r.UpdateDataWithHeaders(path, data, nil)
}

/*
UpdateDataWithHeaders sends a PUT request to the server with the given data and
returns the response body. If the request fails, it will return an
error.

The request will automatically refresh the token if it is expired.

Parameter:

	path - The path to send the request to
	data - The data to send in the request body
	headers - The headers to send with the request

Return:

	- The response body
	- An error if the request fails
*/
func (r *HTTPReq) UpdateDataWithHeaders(path string, data []byte, headers map[string]string) ([]byte, error) {
	if err := r.checkToken(); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return r.put(path, data, headers)
}

/*
PatchData sends a PATCH request to the server with the given data and
returns the response body. If the request fails, it will return an
error.

The request will automatically refresh the token if it is expired.

Parameter:

	path - The path to send the request to
	data - The data to send in the request body

Return:

	- The response body
	- An error if the request fails
*/
func (r *HTTPReq) PatchData(path string, data []byte) ([]byte, error) {
	return r.PatchDataWithHeaders(path, data, nil)
}

/*
PatchDataWithHeaders sends a PATCH request to the server with the given data and
headers, and returns the response body. If the request fails, it will return an
error.

The request will automatically refresh the token if it is expired.

Parameter:

	path - The path to send the request to
	data - The data to send in the request body
	headers - The headers to send with the request

Return:

	- The response body
	- An error if the request fails
*/
func (r *HTTPReq) PatchDataWithHeaders(path string, data []byte, headers map[string]string) ([]byte, error) {
	if err := r.checkToken(); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return r.patch(path, data, headers)
}

func (r *HTTPReq) post(path string, data []byte, headers map[string]string) ([]byte, error) {
	return r.send(Post, path, data, headers)
}

func (r *HTTPReq) put(path string, data []byte, headers map[string]string) ([]byte, error) {
	return r.send(Put, path, data, headers)
}

func (r *HTTPReq) patch(path string, data []byte, headers map[string]string) ([]byte, error) {
	return r.send(Patch, path, data, headers)
}

func (r *HTTPReq) get(path string, headers map[string]string) ([]byte, error) {
	return r.send(Get, path, nil, headers)
}

func (r *HTTPReq) send(method, path string, data []byte, headers map[string]string) ([]byte, error) {
	dataRaw, err := r.request(method, path, data, headers)
	if err != nil {
		err = fmt.Errorf("%s %w, err: %v", method, errSendFail, err)

		// reset token
		r.User.Token = ""
		r.User.Expire = time.Now().Unix()
	}

	return dataRaw, err
}
