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
  background-image: url("https://domain.com/30ce6ec8-1ca0-4dee-a4b0-b56fd4adf731");
  background-size: cover;
  background-position: center;
  background-repeat: no-repeat;
}
```

## .env

```text
WEB_LISTEN=127.0.0.1:8000
```
