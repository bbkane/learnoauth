# a01-blog

https://sharmarajdaksh.github.io/blog/github-oauth-with-go

https://www.sohamkamani.com/golang/oauth/

# a02-wtf

https://github.com/settings/applications/1818912

The goal here is to get auth1 functionality with mux and google oauth2, similar to warg.

Then I can add the session stuff as well as state param

# a03-securecookie

https://developpaper.com/go-one-library-per-day-gorilla-securecookie/

Let's just copy this :)

```
$ curl -i http://localhost:8080/set
HTTP/1.1 200 OK
Set-Cookie: user=MTY0Mzg0MTU3OHx6d3V4anI1QU9vdXlUQTBPVWhEd2U3VUw0RGZsWmlkNG9QaEM5LWEtWEVoa0NzYWJ5c0o4ZFhHVklvMUFGNXVqQkdQV0IyQlhHV05DT0xaY2dpZz18PI_0-opCO2ynG5JNeG-2qa38cLwJTkByv1EC5lSROdE=; Path=/; HttpOnly; Secure
Date: Wed, 02 Feb 2022 22:39:38 GMT
Content-Length: 12
Content-Type: text/plain; charset=utf-8

Hello World
14:39:38.131 PST mac02:~
$ curl -i http://localhost:8080/get --cookie 'user=MTY0Mzg0MTU3OHx6d3V4anI1QU9vdXlUQTBPVWhEd2U3VUw0RGZsWmlkNG9QaEM5LWEtWEVoa0NzYWJ5c0o4ZFhHVklvMUFGNXVqQkdQV0IyQlhHV05DT0xaY2dpZz18PI_0-opCO2ynG5JNeG-2qa38cLwJTkByv1EC5lSROdE=; Path=/; HttpOnly; Secure'
HTTP/1.1 200 OK
Date: Wed, 02 Feb 2022 22:40:04 GMT
Content-Length: 14
Content-Type: text/plain; charset=utf-8

name:dj age:18%
```

# a04-cookie

- set cookie on login
- save the following into a data structure
  - user auth information from /login/github/callback (token)
  - username
  - cookie
- redirect the user a page showing GitHub info if they're logged in

https://pkg.go.dev/github.com/benbjohnson/wtf#Auth

Ok, it looks like I'm setting the cookie in the response, but the browser isn't sending the cookie back. This leads to an Oauth state mismatch

Let's make a "set and read cookie" folder until I can get back to this...
