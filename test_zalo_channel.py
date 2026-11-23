import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
import iuh_telegram_bot as bot
from zalo_channel import ZaloChannel, issue_link


class ZaloTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.env = patch.dict(os.environ, {'SUBSCRIBER_STATE_KEY': 'k' * 48})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.path = Path(self.folder.name) / 'state.json'
        self.original = {'enabled': True, 'sent': ['old'], 'mssv': 'student', 'password': 'private'}
        bot.write_subscribers(self.path, 'tg', {'subscribers': {'12345': self.original.copy()}, 'offset': 99})
        self.channel = ZaloChannel(bot, self.path, 'tg', 'zalo-secret')
        self.send = patch.object(self.channel, 'send')
        self.sent = self.send.start()
        self.addCleanup(self.send.stop)
        self.counter = 0

    def command(self, text, chat='zalo.hex'):
        self.counter += 1
        update = {'event_name': 'message.text.received', 'message': {
            'message_id': str(self.counter), 'chat': {'id': chat, 'chat_type': 'PRIVATE'}, 'text': text}}
        self.channel.handle(Mock(), update)
        return update

    def test_link_preserves_telegram_credentials_offset_and_encryption(self):
        code = issue_link(bot, self.path, 'tg', '12345')
        self.command('/link ' + code)
        data = self.channel.read()
        self.assertEqual(data['subscribers']['12345'], self.original)
        self.assertEqual(data['offset'], 99)
        self.assertEqual(data['zalo_subscribers']['zalo.hex']['telegram_id'], '12345')
        stored = self.path.read_text()
        self.assertNotIn('private', stored)
        self.assertNotIn('zalo.hex', stored)
        self.assertNotIn(code, stored)
        self.command('/link ' + code, 'attacker')
        self.assertNotIn('attacker', self.channel.read()['zalo_subscribers'])

    def test_expired_and_superseded_codes_cannot_link(self):
        with patch('zalo_channel.time.time', return_value=100):
            old = issue_link(bot, self.path, 'tg', '12345')
            code = issue_link(bot, self.path, 'tg', '12345')
        self.command('/link ' + old)
        with patch('zalo_channel.time.time', return_value=701):
            self.command('/link ' + code)
        self.assertEqual(self.channel.read()['zalo_subscribers'], {})

    def test_delivery_routes_personal_and_shared_events_without_duplicates(self):
        self.command('/start')
        code = issue_link(bot, self.path, 'tg', '12345')
        self.command('/link ' + code, 'personal')
        event = dict(id='new', title='Activity', semester='1', points='2', deadline='Tomorrow')
        self.sent.reset_mock()
        self.channel.deliver(Mock(), '12345', [event])
        self.channel.deliver(Mock(), '12345', [event])
        self.assertEqual(self.sent.call_count, 1)
        self.assertEqual(self.sent.call_args.args[1], 'personal')
        self.channel.deliver(Mock(), None, [event])
        self.assertEqual(self.sent.call_args.args[1], 'zalo.hex')

    def test_failed_delivery_can_retry_and_does_not_mark_sent(self):
        self.command('/start')
        self.sent.side_effect = RuntimeError('offline')
        event = dict(id='new', title='Activity', semester='1', points='2', deadline='Tomorrow')
        self.channel.deliver(Mock(), None, [event])
        self.assertEqual(self.channel.read()['zalo_subscribers']['zalo.hex']['sent'], [])
        self.sent.side_effect = None
        self.channel.deliver(Mock(), None, [event])
        self.assertEqual(self.channel.read()['zalo_subscribers']['zalo.hex']['sent'], ['new'])

    def test_stop_unlink_and_duplicate_message(self):
        update = self.command('/start')
        self.channel.handle(Mock(), update)
        self.assertEqual(self.sent.call_count, 1)
        self.command('/stop')
        self.assertFalse(self.channel.read()['zalo_subscribers']['zalo.hex']['enabled'])
        self.command('/start')
        self.command('/unlink')
        self.assertNotIn('telegram_id', self.channel.read()['zalo_subscribers']['zalo.hex'])

    def test_linked_zalo_keeps_receiving_when_telegram_is_paused(self):
        code = issue_link(bot, self.path, 'tg', '12345')
        self.command('/link ' + code)
        data = self.channel.read()
        data['subscribers']['12345']['enabled'] = False
        self.channel.write(data)
        with patch.object(bot, 'get_events', return_value=[]), patch.object(bot, 'deliver_events') as tg:
            bot.check_once(Mock(), self.path, 'common', 'pass', 'tg', zalo_channel=self.channel)
        self.assertIn('12345', self.channel.source_ids())
        self.assertEqual(tg.call_args.args[3], '12345')

    def test_request_errors_never_disclose_token(self):
        session = Mock()
        session.post.side_effect = requests.ConnectionError('https://example/botzalo-secret')
        with self.assertRaises(RuntimeError) as error:
            self.channel.api(session, 'getMe')
        self.assertNotIn('zalo-secret', str(error.exception))

    def test_official_polling_shape_and_json_payload(self):
        session = Mock()
        session.post.return_value.ok = True
        session.post.return_value.json.return_value = {'ok': True, 'result': {'event_name': 'message.text.received'}}
        result = self.channel.api(session, 'getUpdates', timeout=20)
        self.assertIsInstance(result, dict)
        self.assertEqual(session.post.call_args.kwargs['json'], {'timeout': 20})
        self.assertEqual(session.post.call_args.kwargs['timeout'], 40)

    def test_group_messages_cannot_subscribe(self):
        self.channel.handle(Mock(), {'event_name': 'message.text.received', 'message': {
            'message_id': 'group', 'chat': {'id': 'group-id', 'chat_type': 'GROUP'}, 'text': '/start'}})
        self.sent.assert_not_called()
        self.assertNotIn('zalo_subscribers', self.channel.read())

    def test_missing_webhook_is_not_an_authentication_failure(self):
        session = Mock()
        session.post.return_value.ok = True
        session.post.return_value.json.return_value = {'ok': False, 'error_code': 404, 'description': 'Not Found'}
        self.assertIsNone(self.channel.api(session, 'getWebhookInfo'))
        with self.assertRaises(RuntimeError):
            self.channel.api(session, 'getMe')


if __name__ == '__main__':
    unittest.main()
