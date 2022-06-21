from typing import Union

from fastapi import FastAPI, Header, Body, Request, Response, Cookie
from pydantic import BaseModel

from google.oauth2 import id_token
from google.auth.transport import requests

import jwt

from fastapi.responses import HTMLResponse

from datetime import datetime, timezone, timedelta

app = FastAPI()

SECRET = "test-secret"
CLIENT_ID = "568551555512-k1a9ihq9g7d9r7i41d5s8411s3m3vpjr.apps.googleusercontent.com"

AUTH_SITE = """
<html>
    <head>
    </head>

    <body>
        <script src="https://accounts.google.com/gsi/client" async defer></script>
        <script>
        function handleCredentialResponse(response) {{
          var xhr = new XMLHttpRequest();
          xhr.open('GET', 'http://localhost:8080/auth?credential=' + response.credential);
          //xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
          xhr.onload = function() {{
            console.log('Signed in as: ' + xhr.responseText);
          }};
          xhr.send();
          //xhr.send('credential=' + response.credential);
        }}
            //callback: handleCredentialResponse,
        window.onload = function () {{
          google.accounts.id.initialize({{
            client_id: "{}",
            callback: handleCredentialResponse,
          }});
          google.accounts.id.renderButton(
            document.getElementById("buttonDiv"),
            {{ theme: "outline", size: "large" }}  // customization attributes
          );
          google.accounts.id.prompt(); // also display the One Tap dialog
        }}
        </script>
    <div id="buttonDiv"></div>
    </body>
</html>
""".format(CLIENT_ID)

@app.get("/login", response_class=HTMLResponse)
async def login():
    return AUTH_SITE

@app.post("/auth2")
async def auth():
    print("HERE", data.credential)
    return {"Hello": credential }

@app.get("/auth")
async def auth(credential: str, req : Request, resp : Response):
    # print("HERE", credential, req)
    userid = "NONE"
    try:
        # Specify the CLIENT_ID of the app that accesses the backend:
        #idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
        idinfo = id_token.verify_oauth2_token(credential, requests.Request(), CLIENT_ID)

        # Or, if multiple clients access the backend server:
        # idinfo = id_token.verify_oauth2_token(token, requests.Request())
        # if idinfo['aud'] not in [CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]:
        #     raise ValueError('Could not verify audience.')

        # If auth request is from a G Suite domain:
        # if idinfo['hd'] != GSUITE_DOMAIN_NAME:
        #     raise ValueError('Wrong hosted domain.')

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        userid = idinfo['given_name']
        encoded_jwt = jwt.encode({
                                  "email" : idinfo['email'], 
                                  "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=60)
                                 }, 
                                 SECRET, 
                                 algorithm="HS256")
        resp.set_cookie(key="mlexchange_user", value=idinfo['given_name'])
        resp.set_cookie(key="mlexchange_token", value=encoded_jwt)
    except ValueError as e:
        # Invalid token
        print("HERE", repr(e))
        pass

    return {"Hello": userid }

@app.get("/private/auth")
def auth_token(request: Request, response: Response, cookies : Union[str, None] = Cookie(default=None)):
    """ generate a new access token given a refresh token """
    my_header = request.headers.get('MLEX_HOST', "").replace(".mlsandbox.als.lbl.gov", "")
    my_header_2 = request.headers.get('Authorization', "")
    request_uri = request.headers.get('X-Original-URI', "")

    print("URI", request_uri)

    try:
        cookies = str(request.headers.get('cookie', ''))
        cookies = cookies.split(';')
        cookies = [ cookie.strip() for cookie in cookies ]

        for cookie in cookies:
          key, value = cookie.split("=")
          if key == "mlexchange_token":
              # print("YAY", value)
              try:
                  decoded_value = jwt.decode(value, SECRET, algorithms=["HS256"])
              except jwt.ExpiredSignatureError:
                  # Signature has expired
                  ...
                  response.headers['my_custom_header'] = "Expired"
                  response.status_code = 200
                  return ""

              # print("DECODED", decoded_value)
              response.headers['my_custom_header'] = request_uri
              response.status_code = 200
              return ""
    except:
        pass

    response.headers['my_custom_header'] = "Back to Main"
    response.status_code = 200

    return ""


