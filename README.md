# entra-phishing-detection

## LICENSE

[This work](https://github.com/firefart/entra-phishing-detection) © 2025 by [Christian Mehlmauer](https://github.com/firefart) is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/?ref=chooser-v1)

## Description

This project implements an entra phishing protection. It's not bulletproof but can detect simple MITM scenarios by checking the `Referer` header to be a valid microsoft url.
This can prevent EvilNGINX attacks by modifying the background image, but can easily be bypassed. If an invalid referer is detected, we will show a stange image to prevent the user entering some credentials (currently only available in german). You can implement additional alerts using the provided access logs, like a successful login without an request to this service, or a request from a server ip range.
The company branding CSS is no fully supported CSS as it's parsed by javascript and you can only [style the predefined elements](https://learn.microsoft.com/en-us/entra/fundamentals/reference-company-branding-css-template). This prevents stuff like including a dynamic CSS so we can only work with the background.

## CSS to include

Save the following content to `custom.css` and upload it on the `Customer Branding` page in the entra portal.

```css
.ext-sign-in-box {
  background-color: white;
  background-image: url("https://domain.com/image_path");
  background-size: cover;
  background-position: center;
  background-repeat: no-repeat;
}
```

## Configuration

Copy the `config.sample.json`to `config.json` and `Caddyfile.example` to `Caddyfile` and adopt according to your needs.

## CLI Options

Use `--help` to show all available flags and default values

| Value          | Description                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------- |
| -listen        | the ip and port to listen to                                                                            |
| -listenMetrics | the ip and port to listen to for metrics (this endpoint should not be exposed directly to the internet) |
| -config        | the config filename                                                                                     |
| -debug         | enable debug output                                                                                     |
| -json          | print all logs in json format so it can be parsed easily                                                |
| -configcheck   | checks the configfile and exits with an error code                                                      |
| -version       | shows version information and exits                                                                     |

## config.json

| Value                          | Description                                                                                                                                          |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| server.graceful_timeout        | graceful timeout when stopping the server                                                                                                            |
| server.secret_key_header_name  | used for the middleware to secure the version endpoint. Header name that must be included                                                            |
| server.secret_key_header_value | The corresponding header value to secret_key_header_name                                                                                             |
| server.ip_header               | If you are running behind a reverse proxy, set this header to the custom IP-header and make sure it's only from trusted proxies (via your Caddyfile) |
| server.path_image              | Path to the image url. Should be a random url like a GUID otherwise scanners will trigger your app easily. Please exclude the leading slash          |
| server.path_health             | Path to the health check url (need to match the .env file)                                                                                           |
| server.path_version            | Path to the version endpoint                                                                                                                         |
| timeout                        | general request timeout                                                                                                                              |
| allowed_origins                | array of hostnames that are valid. Defaults to login.microsoftonline.com                                                                             |

## .env

```text
WEB_LISTEN=127.0.0.1:8000
METRICS_LISTEN=127.0.0.1:8001
HEALTHCHECK=http://localhost:8000/health_path
```

| Value          | Description                                                                                                                                                                       |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WEB_LISTEN     | Listening Port on the local machine where Caddy should be exposed. If you only specify a port, the port will be available on all interfaces                                       |
| METRICS_LISTEN | Listening port where caddy should expose the prometheus metrics. Be sure to configure an ip ACL or any other form of authentication so the metrics are not exposed to the public. |
| HEALTHCHECH    | this needs to be the full url matching the `server.path_health` property from `config.json`                                                                                       |
