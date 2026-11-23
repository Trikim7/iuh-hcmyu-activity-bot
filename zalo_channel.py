"""Zalo Bot API channel; state shares the existing encrypted subscriber store."""
import hashlib
import os
import re
import secrets
import threading
import time

import requests


def issue_link(bot, path, token, chat_id, legacy=None):
    if len(os.environ.get('SUBSCRIBER_STATE_KEY', '')) < 32:
        raise RuntimeError('Cần khóa mã hóa riêng để liên kết Zalo.')
    code = secrets.token_urlsafe(18)
    with bot.STATE_LOCK:
        data = bot.read_subscribers(bot.read_state(path), token, legacy)
        links = data.setdefault('zalo_links', {})
        now = time.time()
        data['zalo_links'] = {k: v for k, v in links.items()
                              if v['expires'] > now and v['telegram_id'] != chat_id}
        data['zalo_links'][hashlib.sha256(code.encode()).hexdigest()] = {
            'telegram_id': chat_id, 'expires': now + 600}
        bot.write_subscribers(path, token, data)
    return code


class ZaloChannel:
    def __init__(self, bot, path, telegram_token, token, legacy=None):
        self.bot, self.path, self.telegram_token, self.token = bot, path, telegram_token, token
        self.legacy = legacy
        self.stop_event = threading.Event()

    def read(self):
        return self.bot.read_subscribers(self.bot.read_state(self.path), self.telegram_token, self.legacy)

    def write(self, data):
        self.bot.write_subscribers(self.path, self.telegram_token, data)

    def api(self, session, method, **payload):
        try:
            response = session.post(f'https://bot-api.zaloplatforms.com/bot{self.token}/{method}',
                                    json=payload, timeout=40)
            if method == 'getUpdates' and response.status_code == 408:
                return None
            if not response.ok:
                raise RuntimeError(f'Zalo {method}: HTTP {response.status_code}.')
            body = response.json()
            if not body.get('ok'):
                # Official error-code docs: no incoming event during long polling.
                if method == 'getUpdates' and str(body.get('error_code')) == '408':
                    return None
                # Live API returns 404/Not Found when no webhook exists.
                if method == 'getWebhookInfo' and body.get('error_code') == 404:
                    return None
                detail = str(body.get('description') or body.get('message') or '')
                detail = re.sub(r'https?://\S+', '[URL]', detail.replace(self.token, '[TOKEN]'))[:200]
                raise RuntimeError(f"Zalo {method}: lỗi {body.get('error_code', 'unknown')} {detail}")
            return body.get('result')
        except (requests.RequestException, ValueError):
            # Requests exceptions contain credential-bearing URLs. Never surface them.
            raise RuntimeError(f'Không kết nối được Zalo khi gọi {method}.') from None

    def send(self, session, chat_id, text):
        self.api(session, 'sendMessage', chat_id=chat_id, text=text[:2000])

    def handle(self, session, update):
        message = update.get('message') or {}
        chat = message.get('chat') or {}
        chat_id, message_id = chat.get('id'), message.get('message_id')
        if (update.get('event_name') != 'message.text.received'
                or chat.get('chat_type') != 'PRIVATE' or not isinstance(chat_id, str)
                or not chat_id or not isinstance(message_id, str) or not message_id):
            return
        parts = (message.get('text') or '').strip().split(maxsplit=1)
        command = parts[0].lower() if parts else ''
        with self.bot.STATE_LOCK:
            data = self.read()
            seen = data.setdefault('zalo_seen', [])
            if message_id in seen:
                return
            people = data.setdefault('zalo_subscribers', {})
            person = people.get(chat_id)
            if command == '/start':
                person = people.setdefault(chat_id, {'enabled': True, 'sent': []})
                person['enabled'] = True
                reply = 'Xin chào! Đã bật thông báo hoạt động IUH trên Zalo. Gửi /help để xem hướng dẫn.'
            elif command == '/stop':
                if person:
                    person['enabled'] = False
                reply = 'Đã tạm dừng thông báo Zalo. Gửi /start để bật lại.'
            elif command == '/status':
                reply = ('Đang nhận thông báo.' if person and person['enabled'] else 'Thông báo đang tắt.')
                reply += (' Nguồn: tài khoản IUH đã liên kết từ Telegram.'
                          if person and person.get('telegram_id') else ' Nguồn: danh sách chung.')
            elif command == '/link' and len(parts) == 2:
                digest = hashlib.sha256(parts[1].encode()).hexdigest()
                link = data.get('zalo_links', {}).get(digest)
                if not link or link['expires'] <= time.time():
                    reply = 'Mã không hợp lệ hoặc đã hết hạn. Lấy mã mới bằng /link trên Telegram.'
                else:
                    person = people.setdefault(chat_id, {'enabled': True, 'sent': []})
                    if person.get('telegram_id') != link['telegram_id']:
                        person['sent'] = []
                    person.update(telegram_id=link['telegram_id'], enabled=True)
                    del data['zalo_links'][digest]
                    reply = 'Đã liên kết! Zalo sẽ nhận hoạt động theo cùng tài khoản IUH trên Telegram.'
            elif command == '/unlink':
                if person:
                    person.pop('telegram_id', None)
                    person['sent'] = []
                reply = 'Đã gỡ liên kết Zalo; nguồn thông báo trở về danh sách chung.'
            else:
                reply = ('/start — bật thông báo\n/stop — tạm dừng\n/status — trạng thái\n'
                         '/link MA — liên kết bằng mã lấy từ /link trên Telegram (hạn 10 phút)\n'
                         '/unlink — gỡ liên kết\n/help — hướng dẫn\n'
                         'Không gửi mật khẩu IUH vào Zalo. Bot cộng đồng, không phải kênh chính thức IUH.')
            # Persist once before acknowledgement: redelivery must not consume a code twice.
            data['zalo_seen'] = (seen + [message_id])[-500:]
            self.write(data)
        self.send(session, chat_id, reply)

    def source_ids(self):
        with self.bot.STATE_LOCK:
            return {p['telegram_id'] for p in self.read().get('zalo_subscribers', {}).values()
                    if p['enabled'] and p.get('telegram_id')}

    def needs_shared(self):
        with self.bot.STATE_LOCK:
            data = self.read()
            return any(p['enabled'] and (not p.get('telegram_id') or not
                       data['subscribers'].get(p['telegram_id'], {}).get('mssv'))
                       for p in data.get('zalo_subscribers', {}).values())

    def deliver(self, session, source_id, events):
        with self.bot.STATE_LOCK:
            data = self.read()
            for chat_id, person in data.get('zalo_subscribers', {}).items():
                linked = data['subscribers'].get(person.get('telegram_id'), {})
                effective = person.get('telegram_id') if linked.get('mssv') and linked.get('password') else None
                if not person['enabled'] or effective != source_id:
                    continue
                for event in events:
                    key = str(event['id'])
                    if key in person['sent']:
                        continue
                    try:
                        self.send(session, chat_id, f"Hoạt động IUH có thể đăng ký:\n{event['title']}\n"
                                  f"Học kỳ: {event['semester']} | Điểm: {event['points']}\n"
                                  f"Hạn đăng ký: {event['deadline']}\n{self.bot.EVENT_URL}")
                    except RuntimeError:
                        print('Chưa gửi được Zalo; sẽ thử lại ở lượt sau.')
                        break
                    person['sent'].append(key)
                    self.write(data)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()

    def stop(self):
        self.stop_event.set()

    def run(self):
        with requests.Session() as session:
            try:
                self.api(session, 'getMe')
                if (self.api(session, 'getWebhookInfo') or {}).get('url'):
                    print('Zalo: webhook đang bật; chưa chạy polling để tránh xung đột.')
                    return
                print('Zalo: token hợp lệ, đang nhận lệnh.')
            except RuntimeError as error:
                print(str(error))
            while not self.stop_event.is_set():
                try:
                    update = self.api(session, 'getUpdates', timeout=20)
                except RuntimeError as error:
                    # api() sanitizes token-bearing URLs and API descriptions.
                    print(f'Zalo nhận lệnh: {error} Thử lại sau 5 giây.')
                    self.stop_event.wait(5)
                    continue
                if not isinstance(update, dict):
                    self.stop_event.wait(1)
                    continue
                try:
                    self.handle(session, update)
                except (RuntimeError, ValueError, OSError) as error:
                    # Processing errors can contain user input: log only the type.
                    print(f'Zalo xử lý lệnh: {type(error).__name__}; kiểm tra lưu trạng thái hoặc gửi phản hồi.')
                    self.stop_event.wait(5)
