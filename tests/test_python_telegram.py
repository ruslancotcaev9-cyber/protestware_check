"""Regression controls for Telegram receiver provenance. All input is inert source text."""
from textwrap import dedent
import unittest

import ast_analysis
import protestware_check as scanner
import report_formats


IMPORTS = 'from telegram.ext import Updater as U, MessageHandler as H, Filters, CallbackContext as C\n'
CALLBACK = dedent('''\
    def on_location(update, ctx):
        if country == "ru":
            ctx.bot.send_message(chat_id=chat, text="sample")
        elif country == "it":
            ctx.bot.sendChatAction(chat, "typing")
    ''')
SETUP = dedent('''\
    def setup():
        updater = U(token, use_context=True)
        dp = updater.dispatcher
        dp.add_handler(H(Filters.location, on_location))
    ''')


def telegram(code):
    return [f for f in ast_analysis.scan_python('fixture.py', code, [])
            if f['rule'] in {'NET_DYNAMIC', 'GEO_ACTION'}]


class TelegramTests(unittest.TestCase):
    def test_callback_needs_registration_and_preserves_each_branch(self):
        self.assertEqual(telegram(CALLBACK), [])
        self.assertEqual(telegram(IMPORTS + CALLBACK), [])
        report = scanner.build_report('fixture', [('fixture.py', IMPORTS + CALLBACK + SETUP)], [], [], [],
                                      dependency_mode='off', ast_mode='required')
        findings = {(f['rule'], f['line']): f for f in report['findings'] if f.get('binding_basis')}
        self.assertEqual(set(findings), {('NET_DYNAMIC', 4), ('NET_DYNAMIC', 6), ('GEO_ACTION', 4)})
        sarif = report_formats.sarif(report)['runs'][0]['results']
        for result in (r for r in sarif if r['properties'].get('binding_basis')):
            line = result['locations'][0]['physicalLocation']['region']['startLine']
            rule = result['ruleId']
            f = findings.pop((rule, line))
            method = 'send_message' if line == 4 else 'send_chat_action'
            for key, value in [('resolved_symbol', 'telegram.Bot.' + method), ('binding_certainty', 'possible'),
                               ('binding_basis', 'telegram-handler-registration')]:
                self.assertEqual((f[key], result['properties'][key]), (value, value))
            steps = [('constructor', 8), ('assignment', 9), ('registration', 10)]
            if rule == 'GEO_ACTION':
                steps.append(('guard', 3))
            steps.append(('sink', line))
            self.assertEqual([(x['kind'], x['line']) for x in f['dataflow']], steps)
            hops = result['codeFlows'][0]['threadFlows'][0]['locations']
            self.assertEqual([h['location']['physicalLocation']['region']['startLine'] for h in hops],
                             [n for _, n in steps])
        self.assertFalse(findings)

    def test_qualified_and_forward_annotations_prove_the_parameter(self):
        for imported, annotation in [(IMPORTS, 'C'), (IMPORTS, '"C"'),
                                     ('import telegram.ext as t\n', 't.CallbackContext')]:
            with self.subTest(annotation=annotation):
                code = CALLBACK.replace('update, ctx', 'update, ctx: ' + annotation).replace('send_message', 'sendMessage')
                hits = telegram(imported + code)
                self.assertEqual(len(hits), 3)
                self.assertTrue(all(f['binding_basis'] == 'telegram-context-annotation' and
                                    f['dataflow'][0]['kind'] == 'annotation' and f['dataflow'][0]['line'] == 2 for f in hits))

    def test_module_registration_and_direct_dispatcher_with_keywords(self):
        setup = ('up = U(token=token, use_context=True)\n'
                 'up.dispatcher.add_handler(handler=H(callback=on_location, filters=Filters.location), group=1)\n')
        hits = telegram(IMPORTS + CALLBACK + setup)
        self.assertEqual(len(hits), 3)
        self.assertEqual([h['kind'] for h in hits[0]['dataflow']][:2], ['constructor', 'registration'])
        self.assertEqual(telegram(IMPORTS + setup + CALLBACK), [])

    def test_foreign_or_unbound_types_and_sdk_constants_do_not_prove_a_receiver(self):
        source = CALLBACK.replace('text="sample"', 'text="sample", parse_mode=telegram.ParseMode.MARKDOWN')
        for before, callback, after in [
                ('import telegram\n', source, ''),
                ('from other import CallbackContext as C\n' + 'import telegram\n',
                 source.replace('update, ctx', 'update, ctx: C'), ''),
                (IMPORTS + 'C = Other\n', source.replace('update, ctx', 'update, ctx: C'), ''),
                (IMPORTS, source.replace('update, ctx', 'update, ctx: Other'), SETUP),
                (IMPORTS, source, SETUP.replace('def setup():', 'def setup(H):')),
                (IMPORTS, source, SETUP.replace('def setup():', 'def setup(on_location):')),
                (IMPORTS, source, SETUP.replace('def setup():', 'def setup(U):')),
                (IMPORTS, source, SETUP.replace('    dp.add_handler(H(Filters.location, on_location))',
                                                '    H(Filters.location, on_location)')),
                (IMPORTS, source, SETUP.replace('dp = updater.dispatcher', 'dp = custom.dispatcher')),
                (IMPORTS, source, SETUP.replace('use_context=True', 'use_context=False')),
                (IMPORTS, source, SETUP.replace('use_context=True', 'use_context=flag')),
                (IMPORTS, source, SETUP.replace('use_context=True', 'use_context=True, context_types=custom')),
                (IMPORTS, source, SETUP.replace('U(token,', 'U(bot=custom,')),
                (IMPORTS, source, SETUP.replace('    dp.add_handler', '    return\n    dp.add_handler')),
                (IMPORTS.replace('telegram.ext', 'custom.ext') + 'import telegram\n', source, SETUP)]:
            with self.subTest(before=before, after=after):
                self.assertEqual(telegram(before + callback + after), [])

    def test_mutations_and_deferred_or_nested_calls_are_excluded(self):
        for extra in ('ctx = local', 'ctx.bot = local', 'del ctx.bot.send_message',
                      'setattr(ctx.bot, "send_message", local)', 'for ctx in items: pass'):
            with self.subTest(extra=extra):
                self.assertEqual(telegram(IMPORTS + CALLBACK.replace('    if country', '    ' + extra + '\n    if country') + SETUP), [])
        for change in ('    dp = other\n', '    updater = other\n', '    dp.add_handler = other\n',
                       '    updater.dispatcher = other\n'):
            with self.subTest(change=change):
                self.assertEqual(telegram(IMPORTS + CALLBACK + SETUP.replace('    dp.add_handler', change + '    dp.add_handler')), [])
        for body in ('return\n    ctx.bot.send_message(chat, text)', 'lambda: ctx.bot.send_message(chat, text)',
                     '(ctx.bot.send_message(chat, text) for x in items)', 'def inner(): ctx.bot.send_message(chat, text)',
                     'yield ctx.bot.send_message(chat, text)'):
            with self.subTest(body=body):
                self.assertEqual(telegram(IMPORTS + 'def handler(ctx: C):\n    ' + body), [])
        self.assertEqual(telegram(IMPORTS + CALLBACK.replace('def on_location', 'async def on_location') + SETUP), [])

    def test_call_shapes_and_receiver_are_checked(self):
        for call in ('ctx.bot.send_message(chat)', 'ctx.bot.send_message(chat, text, unknown=True)',
                     'ctx.bot.send_message(chat, text, chat_id=chat)', 'ctx.bot.send_message(**values)',
                     'ctx.bot.send_chat_action(*values)', 'other.bot.send_message(chat, text)',
                     'factory(ctx).bot.send_message(chat, text)', 'ctx.bot.send_photo(chat, photo)'):
            with self.subTest(call=call):
                self.assertEqual(telegram(IMPORTS + 'def handle(ctx: C):\n    if country == "ru": ' + call), [])
        for callback in (CALLBACK.replace('update, ctx', 'ctx'), CALLBACK.replace('update, ctx', 'update, ctx, required'),
                         CALLBACK.replace('update, ctx', 'update, *, ctx')):
            with self.subTest(callback=callback):
                self.assertEqual(telegram(IMPORTS + callback + SETUP), [])
