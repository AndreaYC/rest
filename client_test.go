package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mock token data
var mockTokenData = `{
	"token": "mockToken",
	"expire": "2024-09-10T15:04:05Z",
	"error": ""
}`

// test GetToken
func TestGetToken(t *testing.T) {
	// create a mock http server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockTokenData))
		}))
	defer server.Close()

	user := Auth{
		Account:  User{"username": "test", "password": "password"},
		LoginURL: "/login",
	}
	req := NewHTTPReq(server.URL, user, 5, false)

	err := req.GetToken()
	assert.NoError(t, err)
	assert.Equal(t, "mockToken", req.User.Token)
	assert.NotZero(t, req.User.Expire)
}

// test RefreshToken
func TestRefreshToken(t *testing.T) {
	// create a mock http server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockTokenData))
	}))
	defer server.Close()

	user := Auth{
		Account:    User{"username": "test", "password": "password"},
		RefreshURL: "/refresh",
	}
	req := NewHTTPReq(server.URL, user, 5, false)

	err := req.RefreshToken()
	assert.NoError(t, err)
	assert.Equal(t, "mockToken", req.User.Token)
	assert.NotZero(t, req.User.Expire)
}

// test SetData (POST request)
func TestSetData(t *testing.T) {
	// create a mock http server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	user := Auth{
		Token: "mockToken",
	}
	req := NewHTTPReq(server.URL, user, 5, false)

	data := []byte(`{"key":"value"}`)
	resp, err := req.SetData("/data", data)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, strings.Contains(string(resp), "success"))
}

// 測試GetData (GET請求)
func TestGetData(t *testing.T) {
	// create a mock http server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": "mockData"}`))
	}))
	defer server.Close()

	user := Auth{
		Token: "mockToken",
	}
	req := NewHTTPReq(server.URL, user, 5, false)

	resp, err := req.GetData("/data")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, strings.Contains(string(resp), "mockData"))
}

// test requestWithContext
func TestRequestWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": "mockData"}`))
	}))
	defer server.Close()

	req := NewHTTPReq(server.URL, Auth{}, 5, false)

	headers := map[string]string{
		"Custom-Header": "HeaderValue",
	}

	data := []byte(`{"key":"value"}`)

	ctx := context.Background()
	resp, err := req.requestWithContext(ctx, http.MethodPost, "/test", data, headers)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, strings.Contains(string(resp), "mockData"))
}

// test parseToken data
func TestParseToken(t *testing.T) {
	req := NewHTTPReq("http://example.com", Auth{}, 5, false)
	err := req.parseToken([]byte(mockTokenData))
	assert.NoError(t, err)
	assert.Equal(t, "mockToken", req.User.Token)
}

// test checkToken
func TestCheckToken(t *testing.T) {
	req := NewHTTPReq("http://example.com", Auth{
		Token:  "mockToken",
		Expire: time.Now().Add(1 * time.Hour).Unix(),
	}, 5, false)

	err := req.checkToken()
	assert.NoError(t, err)
}
