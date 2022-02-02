# a01-blog

https://sharmarajdaksh.github.io/blog/github-oauth-with-go

https://www.sohamkamani.com/golang/oauth/

# a02-wtf

https://github.com/settings/applications/1818912

The goal here is to get auth1 functionality with mux and google oauth2, similar to warg.

Then I can add the session stuff as well as state param

# a03-cookie

- set cookie on login
- save the following into a data structure
  - user auth information from /login/github/callback (token)
  - username
  - cookie
- redirect the user a page showing GitHub info if they're logged in

https://pkg.go.dev/github.com/benbjohnson/wtf#Auth

Ok, it looks like I'm setting the cookie in the response, but the browser isn't sending the cookie back. This leads to an Oauth state mismatch

Let's make a "set and read cookie" folder until I can get back to this...