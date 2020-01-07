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

# 監聽所有來自 /callback 的 Post Request
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

# 處理訊息
@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    message = TextSendMessage(text=event.message.text)
    line_bot_api.reply_message(event.reply_token, message)

import os
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    app.run(host='127.0.0.1', port=port)
