"""Google OAuth connect flow.

Browsers need plain HTTP redirects, so this is the one user-facing HTTP
surface of the broker: it sends the user to the provider's consent screen and
turns the returned authorization code into envelope-encrypted tokens in
``connected_accounts``. Raw provider tokens exist here only transiently and
never appear in a response, a log line, or an exception message.
"""
