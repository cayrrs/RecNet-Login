from curl_cffi import requests as cffi_requests
import os
import jwt
import datetime
from typing import Optional
from urllib.parse import urlparse, parse_qs
from dotenv import dotenv_values
from .exceptions import *

class RecNetLogin:
    def __init__(self, env_path: str = None):
        """RecNetLogin, used for getting your RecNet bearer token with ease.

        Args:
            env_path (str, optional): Path to an .env.secret file if you stored your cookie there. Defaults to None.

        Attrs:
            client (cffi_requests.Session): curl_cffi session used to fetch the token. Can be reused.

        Raises:
            CookieMissing: Raises when the cookie cannot be found from either a .env.secret file or your system variables.
        """

        # Prioritize local .env.secret files
        env = dotenv_values(env_path if env_path else ".env.secret")

        # Gotten from .env.secret or system variables?
        self.is_local: bool = False

        # Get identity cookie
        key = "RN_SESSION_TOKEN"
        if key in env:
            self.cookie = env[key]
            self.is_local = True
        else:
            # If no local .env.secret file, look for globals
            if key in os.environ:
                self.cookie = os.getenv(key)
            else:
                raise CookieMissing

        # Initialize attributes
        self.client = cffi_requests.Session(impersonate="chrome120")

        # Get CSRF token
        # As of 03/13/25 not required, if this breaks again first try to uncomment the next line
        #self.client.cookies.set("__Host-next-auth.csrf-token", self.get_csrf_token(), domain="rec.net")
        
        # Include session token
        self.client.cookies.set("__Secure-next-auth.session-token", self.cookie, domain="rec.net")

        # Fetch tokens
        self.__token: str = ""
        self.decoded_token: dict = {}

        self.get_token()
        self.get_decoded_token()

        # Update client headers
        self.client.headers.update({
            "Authorization": f"Bearer {self.__token}" 
        })

    def get_csrf_token(self) -> str:
        resp = self.client.get("https://rec.net/api/auth/csrf")
        data = resp.json()
        return data["csrfToken"]

    def get_decoded_token(self) -> Optional[dict]:
        """Returns a decoded bearer token

        Returns:
            Optional[dict]: A decoded token if one exists
        """
        return self.decoded_token

    def get_token(self, include_bearer: bool = False) -> str:
        """Returns and automatically renews your bearer token.

        Args:
            include_bearer (bool, optional): Whether to include the Bearer prefix to the token. Defaults to False.

        Raises:
            InvalidLocalCookie: Raises if your .env.secret cookie is invalid or has expired.
            InvalidSystemCookie: Raises if your system variable cookie is invalid or has expired.

        Returns:
            str: A bearer token.
        """

        # Check if the token has at least 15 minutes of lifetime left
        if int((datetime.datetime.now() + datetime.timedelta(minutes=15)).timestamp()) > self.decoded_token.get("exp", 0):
            # Less than 15 minutes, renew the token

            # Get with cookie
            auth_url = "https://rec.net/api/auth/session"
            resp = self.client.get(auth_url)

            # Get response
            data = resp.json()

            try:
                self.__token = data["accessToken"]
            except KeyError:
                # The cookie has expired or is invalid
                raise InvalidLocalCookie if self.is_local else InvalidSystemCookie

            # Decode it for later
            self.decoded_token = self.__decode_token(self.__token)

        return f"Bearer {self.__token}" if include_bearer else self.__token
    
    def close(self) -> None:
        """Closes the curl_cffi session."""
        self.client.close()

    def __decode_token(self, token: str) -> dict:
        """Decodes bearer tokens

        Args:
            token (str): A bearer token

        Returns:
            dict: Decoded bearer token
        """
        
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded


if __name__ == "__main__":
    rnl = RecNetLogin()

    r = rnl.client.get(
        url="https://accounts.rec.net/account/me", 
        headers={
            # Always run the "get_token" method when using your token!
            # RecNetLogin will automatically renew the token if it has expired.
            "Authorization": rnl.get_token(include_bearer=True)  
        }
    )

    for key, value in r.json().items():
        print(f"{key} = {value}")

    rnl.close()
