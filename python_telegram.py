"""Static receiver proofs for the synchronous python-telegram-bot context API."""
import ast
from collections import Counter

from python_geo import bound_names, dotted_reference, imports, scope_nodes


METHODS = {
    'send_message': 'send_message', 'sendMessage': 'send_message',
    'send_chat_action': 'send_chat_action', 'sendChatAction': 'send_chat_action',
}
CALLBACK_CONTEXT = 'telegram.ext.CallbackContext'


def has_telegram_import(tree):
    return any(origin and origin.split('.')[0] == 'telegram' for node in tree.body
               if isinstance(node, (ast.Import, ast.ImportFrom)) for _, origin in imports(node))


def arguments(call, required, optional=()):
    """Match explicit arguments. Only required parameters may be passed positionally."""
    if not isinstance(call, ast.Call) or len(call.args) > len(required) or any(
            isinstance(arg, ast.Starred) for arg in call.args):
        return None
    supplied = dict(zip(required, call.args))
    for kw in call.keywords:
        if kw.arg in supplied or kw.arg not in required + optional:
            return None
        supplied[kw.arg] = kw.value
    return supplied if all(key in supplied for key in required) else None


def scope_writes(scope):
    """Count bindings and explicit receiver mutations in the same lexical scope."""
    writes = Counter()
    mutated = set()
    for node in scope_nodes(scope.body):
        writes.update(bound_names(node))
        ref = ()
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            ref = dotted_reference(node)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id in {'setattr', 'delattr'} and node.args):
            ref = dotted_reference(node.args[0])
        if ref:
            mutated.add(ref[0])
    return writes, mutated


def initializer(stmt):
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        target = stmt.targets[0]
    elif isinstance(stmt, ast.AnnAssign):
        target = stmt.target
    else:
        return None, None
    return (target.id, stmt.value) if isinstance(target, ast.Name) else (None, None)


def registrations(bindings, scope, visited, writes, mutated):
    """Follow sequential Updater -> dispatcher -> registered MessageHandler statements."""
    updaters = {}
    dispatchers = {}
    for stmt in scope.body:
        name, value = initializer(stmt)
        if name is not None and writes[name] == 1 and name not in mutated:
            if isinstance(value, ast.Call):
                symbol = bindings.resolve_ref(scope, dotted_reference(value.func), value)
                if symbol == 'telegram.ext.Updater':
                    args = arguments(value, ('token',), ('use_context',))
                    flag = args.get('use_context') if args else None
                    if isinstance(flag, ast.Constant) and flag.value is True:
                        updaters[name] = (('constructor', value.lineno, symbol + '(use_context=True)'),)
            else:
                ref = dotted_reference(value)
                if len(ref) == 2 and ref[1] == 'dispatcher' and ref[0] in updaters:
                    dispatchers[name] = (*updaters[ref[0]], ('assignment', stmt.lineno, ref[0] + '.dispatcher'))

        if not isinstance(stmt, ast.Expr) or stmt.value not in visited:
            continue
        call = stmt.value
        ref = dotted_reference(call.func)
        if len(ref) == 2:
            prefix = dispatchers.get(ref[0])
        elif len(ref) == 3 and ref[1] == 'dispatcher':
            prefix = updaters.get(ref[0])
        else:
            continue
        add = arguments(call, ('handler',), ('group',))
        if not prefix or not add or not isinstance(add['handler'], ast.Call):
            continue
        handler = add['handler']
        if bindings.resolve_ref(scope, dotted_reference(handler.func), handler) != 'telegram.ext.MessageHandler':
            continue
        args = arguments(handler, ('filters', 'callback'))
        if not args:
            continue
        callback = bindings.resolve_ref(scope, dotted_reference(args['callback']), handler)
        if callback not in bindings.functions:
            continue
        try:
            bindings.functions[callback].bind(None, None)
        except TypeError:
            continue
        params = [*callback.args.posonlyargs, *callback.args.args]
        if len(params) >= 2:
            yield (callback, params[1].arg), (*prefix, ('registration', call.lineno,
                   'Dispatcher.add_handler(MessageHandler(' + callback.name + '))'))


def annotated_context(bindings, param):
    annotation = param.annotation
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        parts = annotation.value.split('.')
        ref = tuple(parts) if all(part.isidentifier() for part in parts) else ()
    elif isinstance(annotation, ast.Subscript):
        ref = dotted_reference(annotation.value)
    else:
        ref = dotted_reference(annotation)
    return bindings.resolve_ref(bindings.module, ref, param) == CALLBACK_CONTEXT


def operations(bindings, candidates, setups):
    """Yield only methods on an unmodified parameter with an SDK receiver proof."""
    scopes = {scope for scope, _, _ in candidates if scope in bindings.functions}
    facts = {scope: scope_writes(scope) for scope in scopes | set(setups)
             if scope is bindings.module or scope in bindings.functions}
    # A write declared in another scope can also replace setup variables or parameters.
    shared = {name for node in ast.walk(bindings.module) if isinstance(node, (ast.Global, ast.Nonlocal))
              for name in node.names}
    sources = {}
    for scope, visited in setups.items():
        if scope in facts:
            writes, mutated = facts[scope]
            for key, steps in registrations(bindings, scope, visited, writes, mutated | shared):
                sources.setdefault(key, steps)
    proofs = {}
    for scope in scopes:
        writes, mutated = facts[scope]
        for param in (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs):
            if writes[param.arg] or param.arg in mutated or param.arg in shared:
                continue
            key = (scope, param.arg)
            typed = annotated_context(bindings, param)
            if param.annotation is not None and not typed:
                continue
            if key in sources:
                proofs[key] = 'telegram-handler-registration', sources[key]
            elif typed:
                proofs[key] = 'telegram-context-annotation', (('annotation', param.lineno, CALLBACK_CONTEXT),)
    for scope, call, guard in candidates:
        ref = dotted_reference(call.func)
        if (scope, ref[0]) not in proofs:
            continue
        method = METHODS[ref[2]]
        if method == 'send_message':
            args = arguments(call, ('chat_id', 'text'), ('parse_mode', 'entities', 'disable_web_page_preview',
                             'disable_notification', 'reply_to_message_id', 'allow_sending_without_reply',
                             'reply_markup', 'protect_content', 'timeout', 'api_kwargs'))
        else:
            args = arguments(call, ('chat_id', 'action'), ('timeout', 'api_kwargs'))
        if args:
            basis, steps = proofs[scope, ref[0]]
            yield call, guard, 'telegram.Bot.' + method, basis, steps
