import subprocess

from flask import Flask, request, abort

from linebot import (
    LineBotApi, WebhookHandler
)

from linebot.exceptions import (
    InvalidSignatureError
)
from linebot.models import *

app = Flask(__name__)

# Channel Access Token
line_bot_api = LineBotApi('PT3e6BgyMAEb9TZ7wIz9La5dx1DiSJKP+6YELP7FrvQTofSBhPclrC4ccWfi4X2J3IPaNhEKs59PL9rhbOCubmx/n0OWn9+fUXqXgBBGi18cMi5xEprE9YzHmkbh5K6brwFULjAw4jFOi4GknIOlfwdB04t89/1O/w1cDnyilFU=')
# Channel Secret
handler = WebhookHandler('9ca55e3909b7f2c10eeb3a771b0b7fd7')

@app.route("/callback", methods=['POST'])
def callback():
    # get X-Line-Signature header value
    signature = request.headers['X-Line-Signature']
    # get request body as text
    body = request.get_data(as_text=True)
    app.logger.info("Request body: " + body)
    # handle webhook body
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    return 'OK'


@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    # input from LINE msg
    text = event.message.text

    # THANA custormize
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE

    output = subprocess.run(['python','dnac_phrase_control.py', text],  capture_output=True, text=True, shell=True).stdout
    print (output)

    # output to LINE msg
    output = Convert_line_msg(output)
    if type(output) == list:
        for idx_1, item_1 in enumerate(output):
            if item_1 != "":
                line_bot_api.push_message(
                event.source.user_id, [
                    TextSendMessage(text=item_1),
                    ]
                )

def Convert_line_msg(string): 
    output_list = list(string.split("\n\n")) 
    return (output_list)

import os
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 9000))
    app.run(host='127.0.0.1', port=port)

