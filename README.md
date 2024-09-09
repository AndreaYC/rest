# REST Client Package

This package provides a simple REST client for handling authentication, token management, and performing HTTP requests (GET, POST, PUT, PATCH) with support for token-based or basic authentication.

## Features

- Token-based and basic authentication support.
- Methods for token fetching, refreshing, and expiration handling.
- Easily configurable HTTP requests with timeout settings.
- Supports sending and receiving JSON payloads.
- Error handling for common HTTP status codes.

## Installation

You can install this package by running:

```bash
go get git@github.com:AndreaYC/rest
```

## Usage

### 1. Create an HTTP Client Instance

To use this package, you need to create an instance of `HTTPReq` by providing the base URL, user credentials, and timeout settings.

```go
package main

import (
    "fmt"
    "time"
    "your/package/rest"
)

func main() {
    user := rest.Auth{
        Account: map[string]interface{}{
            "username": "your_username",
            "password": "your_password",
        },
        LoginURL:   "https://example.com/login",
        RefreshURL: "https://example.com/refresh",
    }

    // Create a new HTTP client instance
    client := rest.NewHTTPReq("https://api.example.com", user, 30, false)

    // Get a token
    err := client.GetToken()
    if err != nil {
        fmt.Println("Error getting token:", err)
        return
    }

    // Make a GET request
    resp, err := client.GetData("/some/resource")
    if err != nil {
        fmt.Println("Error making GET request:", err)
        return
    }

    fmt.Println("Response:", string(resp))
}
```

### 2. Token Management

The package automatically handles token expiration. When you call any data-related method (`GetData`, `SetData`, `UpdateData`, `PatchData`), the package will automatically check the token's expiration time. If the token is expired, it will attempt to refresh the token. If refreshing fails, it will request a new token.

### 3. Making Requests

This package supports common HTTP methods, including GET, POST, PUT, and PATCH. Each request can include headers and body data.

#### Example: POST Request

```go
data := []byte(`{"key": "value"}`)

resp, err := client.SetData("/resource", data)
if err != nil {
    fmt.Println("Error posting data:", err)
} else {
    fmt.Println("POST Response:", string(resp))
}
```

#### Example: GET Request with Headers

```go
headers := map[string]string{
    "Custom-Header": "HeaderValue",
}

resp, err := client.GetDataWithHeader("/resource", headers)
if err != nil {
    fmt.Println("Error getting data:", err)
} else {
    fmt.Println("GET Response:", string(resp))
}
```

### 4. Refresh Token

The `RefreshToken` method allows you to manually refresh the authentication token:

```go
err := client.RefreshToken()
if err != nil {
    fmt.Println("Error refreshing token:", err)
}
```

## Error Handling

The package provides error handling for common HTTP errors, including:

- `ErrUnauthorized`: Authentication error (HTTP 401)
- `ErrForbidden`: Access forbidden (HTTP 403)
- `ErrURLNotExist`: Resource not found (HTTP 404)
- `ErrBadRequest`: Bad request error (HTTP 400)
- `ErrInternalServer`: Server error (HTTP 500)

Example:

```go
resp, err := client.GetData("/nonexistent/resource")
if err != nil {
    if errors.Is(err, rest.ErrURLNotExist) {
        fmt.Println("Resource not found!")
    } else {
        fmt.Println("Error fetching data:", err)
    }
}
```

## Testing

To run unit tests for the `rest` package, use the following command:

```bash
go test -v ./...
```

### Example Output:

```bash
=== RUN   TestGetToken
--- PASS: TestGetToken (0.00s)
=== RUN   TestRefreshToken
--- PASS: TestRefreshToken (0.00s)
=== RUN   TestSetData
--- PASS: TestSetData (0.00s)
PASS
ok      your/package/rest  0.005s
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

