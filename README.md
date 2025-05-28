# entra-phishing-detection

## LICENSE

[This work](https://github.com/firefart/entra-phishing-detection) © 2025 by [Christian Mehlmauer](https://github.com/firefart) is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/?ref=chooser-v1)

## Description

This project implements an entra phishing protection. It's not bulletproof but can detect simple MITM scenarios by checking the `Referer` header to be a valid microsoft url.
This can prevent EvilNGINX attacks by modifying the background image via custom branding, but can easily be bypassed. If an invalid referer (not `login.microsoftonline.com`) is detected, we will show a strange image to prevent the user entering some credentials (currently only available in german). You can implement additional alerts using the provided access logs, like a successful login without an request to this service, or a request from a server ip range. There are also some exposed metrics to include in your dashboards.
The company branding CSS is no fully supported CSS as it's parsed by javascript and you can only [style the predefined elements](https://learn.microsoft.com/en-us/entra/fundamentals/reference-company-branding-css-template). This prevents stuff like including a dynamic CSS so we can only work with the background.
You can also use this project for multiple clients, just create a subdomain for each one and point them to this server. The logs and metrics will include the calling host and can thus be differentiated.

## Example

![screenshot](screenshot.png)

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
| -config        | the config filename (you can also use env variables instead)                                            |
| -debug         | enable debug output                                                                                     |
| -configcheck   | checks the configfile and exits with an error code                                                      |
| -version       | shows version information and exits                                                                     |

## config.json // env variables

| Value                          | ENV Variable                            | Description                                                                                                                                                                                 |
| ------------------------------ | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| server.listen                  | ENTRA_SERVER_LISTEN                     | the ip and port to listen to                                                                                                                                                                |
| server.listen_metrics          | ENTRA_SERVER_LISTEN__METRICS            | the ip and port to listen to for metrics (this endpoint should not be exposed directly to the internet)                                                                                     |
| server.graceful_timeout        | ENTRA_SERVER_GRACEFUL__TIMEOUT          | graceful timeout when stopping the server                                                                                                                                                   |
| server.secret_key_header_name  | ENTRA_SERVER_SECRET__KEY__HEADER__NAME  | used for the middleware to secure the version endpoint. Header name that must be included                                                                                                   |
| server.secret_key_header_value | ENTRA_SERVER_SECRET__KEY__HEADER__VALUE | The corresponding header value to secret_key_header_name                                                                                                                                    |
| server.ip_header               | ENTRA_SERVER_IP__HEADER                 | If you are running behind a reverse proxy, set this header to the custom IP-header and make sure it's only from trusted proxies (via your Caddyfile)                                        |
| server.host_headers            | ENTRA_SERVER_HOST__HEADERS              | Array of headers to check for the host value, in order of preference (e.g. ["X-Forwarded-Host", "X-Original-Host"]). Leave empty when not exposed via a correctly configured reverse proxy. |
| server.path_image              | ENTRA_SERVER_PATH__IMAGE                | Path to the image url. Should be a random url like a GUID otherwise scanners will trigger your app easily. Please exclude the leading slash                                                 |
| server.path_health             | ENTRA_SERVER_PATH__HEALTH               | Path to the health check url (need to match the .env file)                                                                                                                                  |
| server.path_version            | ENTRA_SERVER_PATH__VERSION              | Path to the version endpoint                                                                                                                                                                |
| logging.access_log             | ENTRA_LOGGING_ACCESS__LOG               | Enable internal access log if no reverse proxy is used                                                                                                                                      |
| logging.json                   | ENTRA_LOGGING_JSON                      | log output in json for easy parsing                                                                                                                                                         |
| logging.log_file               | ENTRA_LOGGING_LOG__FILE                 | log file name to use in addition to stdout, useful in k8s setup with logging sidecar                                                                                                        |
| logging.rotate.enabled         | ENTRA_LOGGING_ROTATE_ENABLED            | enable autoamtic log rotate of the log file, only used if log_file is specified                                                                                                             |
| logging.rotate.max_size        | ENTRA_LOGGING_ROTATE_MAX__SIZE          | Max size in MB before rotation                                                                                                                                                              |
| logging.rotate.max_backups     | ENTRA_LOGGING_ROTATE_MAX__BACKUPS       | Number of backups to keep                                                                                                                                                                   |
| logging.rotate.max_age         | ENTRA_LOGGING_ROTATE_MAX__AGE           | Days to retain old log files                                                                                                                                                                |
| logging.rotate.compress        | ENTRA_LOGGING_ROTATE_COMPRESS           | Enable compression of rotated files                                                                                                                                                         |
| timeout                        | ENTRA_TIMEOUT                           | general request timeout                                                                                                                                                                     |
| allowed_origins                | ENTRA_ALLOWED__ORIGINS                  | array of hostnames that are valid. Defaults to login.microsoftonline.com                                                                                                                    |

## .env for docker-compose use

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
