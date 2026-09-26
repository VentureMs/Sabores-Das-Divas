#!/usr/bin/env python3
"""Sabores das Divas: servidor HTTP + SQLite, somente biblioteca padrão do Python.
Na produção, publicar EXCLUSIVAMENTE atrás de um proxy HTTPS (veja compose.yaml).
"""
from __future__ import annotations

import base64
import datetime as dt
import getpass
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.umask(0o077)
ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('SDD_DATA_DIR', str(ROOT / 'data')))
DB = DATA / 'sabores.sqlite3'
HOST = os.environ.get('SDD_HOST', '0.0.0.0')
PORT = int(os.environ.get('SDD_PORT', '8080'))
ORIGIN = os.environ.get('SDD_PUBLIC_ORIGIN', f'http://127.0.0.1:{PORT}').rstrip('/')
SECURE_COOKIE = os.environ.get('SDD_SECURE_COOKIE', '0' if ORIGIN.startswith('http://127.') else '1') == '1'
LOCATIONS = {'Norte Shopping', 'Shopping da Pedreira', 'Outros'}
CATEGORIES = {'Refeição', 'Sobremesa', 'Sanduíche'}
ROLES = {'admin', 'operador', 'financeiro'}
MAX_BODY = 3_000_000
MONTH_PATTERN = re.compile(r'^\d{4}-(0[1-9]|1[0-2])$')
EMAIL_PATTERN = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
lock = threading.RLock()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def one_id():
    return secrets.token_hex(16)


def valid_date(v):
    if not isinstance(v, str) or len(v) != 10:
        raise ApiError(400, 'Data inválida.')
    try:
        return dt.date.fromisoformat(v).isoformat()
    except ValueError as exc:
        raise ApiError(400, 'Data inválida.') from exc


def str_field(v, label, max_length=200, required=True):
    if not isinstance(v, str) or len(v.strip()) > max_length or (required and not v.strip()):
        raise ApiError(400, f'Informe {label} válido (até {max_length} caracteres).')
    return v.strip()


def int_field(v, label, minimum=0, maximum=100_000_000):
    if not isinstance(v, int) or isinstance(v, bool) or not minimum <= v <= maximum:
        raise ApiError(400, f'{label} inválido.')
    return v


def password_hash(password):
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(password.encode('utf8'), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f'scrypt$16384$8$1${salt.hex()}${hashed.hex()}'


def check_password(password, stored):
    try:
        _, n, r, p, salt, expected = stored.split('$')
        actual = hashlib.scrypt(password.encode('utf8'), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def totp(secret, step):
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, int(step).to_bytes(8, 'big'), hashlib.sha1).digest()
    index = digest[-1] & 15
    value = int.from_bytes(digest[index:index + 4], 'big') & 0x7fffffff
    return f'{value % 1_000_000:06d}'


def verify_totp(secret, code):
    if not isinstance(code, str) or not re.fullmatch(r'\d{6}', code):
        return False
    epoch = int(time.time() // 30)
    return any(hmac.compare_digest(totp(secret, epoch + skew), code) for skew in (-1, 0, 1))


@contextmanager
def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=15, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=15000')
    try:
        yield con
    finally:
        con.close()


def normalized_username(value):
    """The public display name IS the login username (spaces and accents allowed)."""
    value = str_field(value, 'nome do usuário', 100)
    value = ' '.join(value.split())
    if len(value) < 3 or '@' in value or any(ord(x) < 32 for x in value):
        raise ApiError(400, 'Informe um nome de usuário com 3 a 100 caracteres, sem @.')
    return value


def username_key(value):
    """Stable case/accent-insensitive search key for name-based login."""
    text = unicodedata.normalize('NFKD', value.casefold())
    text = ''.join(c for c in text if not unicodedata.combining(c))
    return ' '.join(text.casefold().split())


def available_username(con, source):
    """Find a display/login name for legacy accounts without changing user IDs."""
    base = normalized_username(source)
    for i in range(1, 100_000):
        candidate = base if i == 1 else base[:max(3, 100-len(str(i))-3)] + f' ({i})'
        if not con.execute('SELECT 1 FROM users WHERE username_key=?', (username_key(candidate),)).fetchone():
            return candidate
    raise RuntimeError('Não foi possível gerar nome de usuário único.')


def format_phone(value, strict=False):
    """Brazilian phone mask. Empty is allowed; ambiguous legacy numbers aren't guessed."""
    value = value.strip()
    if not value:
        return ''
    digits = re.sub(r'\D', '', value)
    if digits.startswith('55') and len(digits) in (12, 13):
        digits = digits[2:]
    if len(digits) == 11:
        return f'({digits[:2]}) {digits[2:7]}-{digits[7:]}'
    if len(digits) == 10:
        return f'({digits[:2]}) {digits[2:6]}-{digits[6:]}'
    if strict:
        raise ApiError(400, 'Telefone inválido: informe DDD + 9 dígitos (ex.: (21) 99999-9999), ou deixe em branco.')
    return value


def new_temporary_pin():
    # Cryptographically random, exactly six digits, including potential leading zero.
    return f'{secrets.randbelow(1_000_000):06d}'


def init_db():
    with connect() as con:
        con.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          role TEXT NOT NULL CHECK(role IN ('admin','operador','financeiro')),
          password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          must_change INTEGER NOT NULL DEFAULT 1, totp_secret TEXT,
          totp_pending TEXT, auth_version INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
          csrf TEXT NOT NULL, auth_version INTEGER NOT NULL, expires INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
          principal TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS clients (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, location TEXT NOT NULL,
          store TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
          notes TEXT NOT NULL DEFAULT '', inadimplente INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL, deleted_at TEXT
        );
        CREATE TABLE IF NOT EXISTS products (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
          price_cents INTEGER NOT NULL, active INTEGER NOT NULL,
          updated_at TEXT NOT NULL, deleted_at TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
          id TEXT PRIMARY KEY, date TEXT NOT NULL, client_id TEXT NOT NULL REFERENCES clients(id),
          client_name TEXT NOT NULL, location TEXT NOT NULL, store TEXT NOT NULL DEFAULT '',
          items_json TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
          created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_orders_client_date ON orders(client_id, date);
        CREATE TABLE IF NOT EXISTS payments (
          id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id),
          date TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
          created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
          actor_id TEXT NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL,
          object_type TEXT NOT NULL, object_id TEXT NOT NULL,
          before_json TEXT, after_json TEXT
        );
        ''')
        columns = {r['name'] for r in con.execute('PRAGMA table_info(users)')}
        product_columns = {r['name'] for r in con.execute('PRAGMA table_info(products)')}
        client_columns = {r['name'] for r in con.execute('PRAGMA table_info(clients)')}
        if 'deleted_at' not in client_columns:
            con.execute('ALTER TABLE clients ADD COLUMN deleted_at TEXT')
        if 'deleted_at' not in product_columns:
            con.execute('ALTER TABLE products ADD COLUMN deleted_at TEXT')
        if 'username' not in columns:
            con.execute('ALTER TABLE users ADD COLUMN username TEXT')
        if 'deleted_at' not in columns:
            con.execute('ALTER TABLE users ADD COLUMN deleted_at TEXT')
        if 'username_key' not in columns:
            con.execute('ALTER TABLE users ADD COLUMN username_key TEXT')
        # Migrate access credentials only. Historical user IDs in orders/payments stay unchanged.
        # Moving old usernames to unique placeholders first prevents transient UNIQUE collisions.
        existing = con.execute('SELECT * FROM users ORDER BY created_at,id').fetchall()
        if any((r['deleted_at'] is None and (r['username'] != r['name'] or r['username_key'] != username_key(r['name'])))
               or not r['username_key'] for r in existing):
            with con:
                for row in existing:
                    con.execute('UPDATE users SET username=?,username_key=? WHERE id=?',
                                ('migracao_'+row['id'], 'migracao_'+row['id'], row['id']))
                con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)')
                con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_key ON users(username_key)')
                for row in existing:
                    if row['deleted_at'] is not None:
                        label = 'deleted_'+row['id']
                        con.execute('UPDATE users SET username=?,username_key=? WHERE id=?',
                                    (label, label, row['id']))
                    else:
                        # In the rare case of duplicate names, distinguish only the duplicate.
                        label = available_username(con, row['name'])
                        con.execute('UPDATE users SET name=?,username=?,username_key=? WHERE id=?',
                                    (label, label, username_key(label), row['id']))
        else:
            con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)')
            con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_key ON users(username_key)')


def dump(row):
    return dict(row) if row is not None else None


def get_client(r):
    return {'id': r['id'], 'name': r['name'], 'location': r['location'], 'store': r['store'],
            'phone': format_phone(r['phone']), 'notes': r['notes'], 'inadimplente': bool(r['inadimplente']),
            'archived': r['deleted_at'] is not None}


def get_product(r):
    return {'id': r['id'], 'name': r['name'], 'category': r['category'],
            'priceCents': r['price_cents'], 'active': bool(r['active']) and r['deleted_at'] is None,
            'archived': r['deleted_at'] is not None}


def get_order(r, payments, include_payments=True):
    o = {'id': r['id'], 'date': r['date'], 'clientId': r['client_id'],
         'clientName': r['client_name'], 'location': r['location'], 'store': r['store'],
         'items': json.loads(r['items_json']), 'notes': r['notes'],
         'createdAt': r['created_at'], 'createdBy': r['created_by'],
         'createdByName': r['creator_name'] or 'Usuário não identificado', 'updatedAt': r['updated_at']}
    if include_payments:
        o['payments'] = payments.get(r['id'], [])
    else:
        o['paidLocked'] = bool(payments.get(r['id']))
    return o


def json_data(con, role, user_id=None):
    customers = [get_client(r) for r in con.execute('SELECT * FROM clients WHERE deleted_at IS NULL ORDER BY name COLLATE NOCASE')]
    products = [get_product(r) for r in con.execute('SELECT * FROM products ORDER BY category,name')]
    include = role != 'operador'
    payments = {}
    for p in con.execute('SELECT * FROM payments ORDER BY created_at, id'):
        if include:
            payments.setdefault(p['order_id'], []).append({'id': p['id'], 'date': p['date'], 'amountCents': p['amount_cents']})
        else:
            payments.setdefault(p['order_id'], []).append(True)
    if role == 'operador':
        rows = con.execute('SELECT o.*, u.name AS creator_name FROM orders o LEFT JOIN users u ON u.id=o.created_by WHERE o.created_by=? ORDER BY o.date DESC, o.created_at DESC', (user_id,)).fetchall()
    else:
        rows = con.execute('SELECT o.*, u.name AS creator_name FROM orders o LEFT JOIN users u ON u.id=o.created_by ORDER BY o.date DESC, o.created_at DESC').fetchall()
    orders = [get_order(o, payments, include) for o in rows]
    return {'version': 1, 'clients': customers, 'products': products, 'orders': orders}


def audit(con, actor, event, object_type, object_id, before=None, after=None):
    con.execute('''INSERT INTO audit(at, actor_id, actor_email, event, object_type, object_id, before_json, after_json)
                   VALUES(?,?,?,?,?,?,?,?)''',
                (now(), actor['id'], actor['email'], event, object_type, object_id,
                 json.dumps(before, ensure_ascii=False) if before is not None else None,
                 json.dumps(after, ensure_ascii=False) if after is not None else None))


def actor_public(user):
    return {'id': user['id'], 'name': user['name'], 'email': user['email'],
            'role': user['role'], 'username': user['username'], 'mustChange': False,
            'totpEnabled': bool(user['totp_secret'])}


def public_user(row):
    return {'id': row['id'], 'name': row['name'], 'email': row['email'], 'username': row['username'], 'role': row['role'],
            'active': bool(row['active']), 'totpEnabled': bool(row['totp_secret']),
            'mustChange': bool(row['must_change'])}


class ApiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message
        super().__init__(message)


def require_role(actor, *roles):
    if actor['role'] not in roles:
        raise ApiError(403, 'Seu perfil não tem permissão para esta operação.')


def parse_client(d, old=None, actor=None):
    if not isinstance(d, dict):
        raise ApiError(400, 'Cadastro inválido.')
    location = str_field(d.get('location'), 'local de venda', 80)
    if location not in LOCATIONS:
        raise ApiError(400, 'Local de venda inválido.')
    delinquent = d.get('inadimplente', False)
    if not isinstance(delinquent, bool):
        raise ApiError(400, 'Marcação de inadimplência inválida.')
    if old is not None and actor and actor['role'] not in ('admin', 'financeiro') and delinquent != bool(old['inadimplente']):
        raise ApiError(403, 'Somente administrador ou financeiro pode alterar inadimplência.')
    if actor and actor['role'] not in ('admin', 'financeiro') and old is None and delinquent:
        raise ApiError(403, 'Somente administrador ou financeiro pode marcar inadimplência.')
    return {'name': str_field(d.get('name'), 'nome do cliente', 100), 'location': location,
            'store': str_field(d.get('store',''), 'loja', 120, False),
            'phone': format_phone(str_field(d.get('phone',''), 'telefone', 32, False), strict=True),
            'notes': str_field(d.get('notes',''), 'observações', 2000, False),
            'inadimplente': int(delinquent)}


def ensure_unique_client_phone(con, phone, current_id=None, previous_phone=None):
    """Reject a telephone already used by another active client, ignoring punctuation.

    A missing phone is allowed. Existing legacy records are compared without
    changing them (older imports may have different telephone masks).
    """
    digits = re.sub(r'\D', '', phone or '')
    if not digits:
        return
    if digits.startswith('55') and len(digits) in (12, 13):
        digits = digits[2:]
    before = re.sub(r'\D', '', previous_phone or '')
    if before.startswith('55') and len(before) in (12, 13):
        before = before[2:]
    # Permite editar observações de cadastros antigos duplicados sem alterar o telefone.
    if current_id is not None and digits == before:
        return
    for other in con.execute('SELECT id, name, phone FROM clients WHERE deleted_at IS NULL AND phone <> ?', ('',)):
        if other['id'] == current_id:
            continue
        existing = re.sub(r'\D', '', other['phone'])
        if existing.startswith('55') and len(existing) in (12, 13):
            existing = existing[2:]
        if existing == digits:
            raise ApiError(409, f'Telefone já cadastrado para o cliente {other["name"]}. Confira o cadastro antes de salvar.')


def parse_product(d):
    if not isinstance(d, dict) or d.get('category') not in CATEGORIES:
        raise ApiError(400, 'Categoria inválida.')
    if not isinstance(d.get('active'), bool):
        raise ApiError(400, 'Disponibilidade inválida.')
    return {'name': str_field(d.get('name'), 'nome do produto', 110),
            'category': d['category'], 'price_cents': int_field(d.get('priceCents'), 'Preço', 0, 10_000_000),
            'active': int(d['active'])}


def parse_order(con, d, old=None):
    if not isinstance(d, dict):
        raise ApiError(400, 'Pedido inválido.')
    day = valid_date(d.get('date'))
    if not isinstance(d.get('items'), list) or not 1 <= len(d['items']) <= 60:
        raise ApiError(400, 'Informe de 1 a 60 itens por pedido.')
    client_id = str_field(d.get('clientId'), 'cliente', 100)
    client = con.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
    if not client or (client['deleted_at'] is not None and old is None):
        raise ApiError(400, 'Cliente não encontrado ou excluído.')
    if old is not None and client_id != old['client_id']:
        raise ApiError(400, 'Não é permitido mudar o cliente de um pedido já registrado.')
    validated = []
    catalog = {r['id']: r for r in con.execute('SELECT * FROM products')}
    for item in d['items']:
        if not isinstance(item, dict):
            raise ApiError(400, 'Item inválido.')
        kind = item.get('kind')
        if kind not in ('menu', 'extra'):
            raise ApiError(400, 'Tipo de item inválido.')
        qty = int_field(item.get('qty'), 'Quantidade', 1, 999)
        price = int_field(item.get('priceCents'), 'Preço', 0, 10_000_000)
        name = str_field(item.get('name'), 'nome do item', 140)
        if kind == 'menu':
            pid = str_field(item.get('productId'), 'produto', 100)
            product = catalog.get(pid)
            if not product:
                raise ApiError(400, 'Produto não cadastrado.')
            historical = False
            if old is not None:
                historical = any(x.get('productId') == pid and x.get('priceCents') == price
                                 and x.get('name') == name for x in json.loads(old['items_json']))
            if not historical and (product['deleted_at'] is not None or not product['active'] or price != product['price_cents'] or name != product['name']):
                raise ApiError(409, 'Produto ou preço do cardápio mudou. Atualize o pedido.')
            validated.append({'kind': 'menu', 'productId': pid, 'name': name,
                              'category': product['category'], 'qty': qty, 'priceCents': price})
        else:
            validated.append({'kind': 'extra', 'productId': None, 'name': name,
                              'category': 'Adicional', 'qty': qty, 'priceCents': price})
    total = sum(i['qty'] * i['priceCents'] for i in validated)
    if total < 1 or total > 999_999_999:
        raise ApiError(400, 'Total do pedido inválido.')
    return {'date': day, 'client_id': client_id, 'client_name': client['name'],
            'location': old['location'] if old else client['location'],
            'store': old['store'] if old else client['store'],
            'items_json': json.dumps(validated, ensure_ascii=False),
            'notes': str_field(d.get('notes',''), 'observações do pedido', 600, False), 'total': total}


def order_due(con, row):
    paid = con.execute('SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE order_id=?', (row['id'],)).fetchone()[0]
    total = sum(i['qty'] * i['priceCents'] for i in json.loads(row['items_json']))
    return total - paid


def check_user_can_edit_order(actor, row, con):
    """Restrict ordinary edits to the responsible user and reject any recorded payment."""
    if actor['role'] in ('operador', 'financeiro') and row['created_by'] != actor['id']:
        raise ApiError(403, 'Você só pode alterar pedidos registrados por você.')
    if con.execute('SELECT 1 FROM payments WHERE order_id=? LIMIT 1', (row['id'],)).fetchone():
        raise ApiError(409, 'Pedido com pagamento registrado não pode ser editado. Corrija somente por procedimento financeiro de estorno.')


def validate_email(email):
    v = str_field(email, 'e-mail', 200).lower()
    if not EMAIL_PATTERN.fullmatch(v):
        raise ApiError(400, 'E-mail inválido.')
    return v


def validate_new_password(password):
    if not isinstance(password, str) or not (4 <= len(password) <= 256):
        raise ApiError(400, 'A senha precisa conter pelo menos 4 caracteres.')
    return password_hash(password)


class Handler(BaseHTTPRequestHandler):
    server_version = 'SaboresDivas/1.0'
    sys_version = ''

    def log_message(self, fmt, *args):
        # Não registra corpo das requisições, senhas nem tokens.
        sys.stderr.write(f'[{now()}] {self.client_address[0]} ' + (fmt % args) + '\n')

    def security_headers(self, content_type='application/json; charset=utf-8'):
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def respond(self, status, body, cookie=None):
        raw = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf8')
        self.send_response(status)
        self.security_headers()
        if cookie is not None:
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def static(self, name, content_type):
        path = (ROOT / 'web' / name).resolve()
        if path.parent != (ROOT / 'web').resolve() or not path.exists():
            raise ApiError(404, 'Arquivo não encontrado.')
        data = path.read_bytes()
        self.send_response(200)
        self.security_headers(content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def json_body(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length < 1 or length > MAX_BODY or 'application/json' not in self.headers.get('Content-Type', '').lower():
            raise ApiError(400, 'Envie dados JSON válidos (até 3 MB).')
        try:
            d = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ApiError(400, 'JSON inválido.') from exc
        if not isinstance(d, dict):
            raise ApiError(400, 'Formato inválido.')
        return d

    def origin_check(self):
        origin = self.headers.get('Origin')
        if origin != ORIGIN:
            raise ApiError(403, 'Origem não autorizada. Verifique o endereço do sistema.')

    def session(self, con):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            token = cookie['sdd_session'].value if 'sdd_session' in cookie else ''
        except http.cookies.CookieError:
            token = ''
        if not token or len(token) > 150:
            raise ApiError(401, 'Faça login para continuar.')
        token_hash = hashlib.sha256(token.encode('ascii', errors='ignore')).hexdigest()
        row = con.execute('''SELECT u.*, s.csrf, s.token_hash FROM sessions s
                             JOIN users u ON u.id=s.user_id
                             WHERE s.token_hash=? AND s.expires>? AND s.auth_version=u.auth_version AND u.active=1''',
                          (token_hash, int(time.time()))).fetchone()
        if not row:
            raise ApiError(401, 'Sessão expirada. Faça login novamente.')
        return row

    def csrf_check(self, actor):
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), actor['csrf']):
            raise ApiError(403, 'Proteção de sessão: recarregue a página e tente novamente.')

    def cookie(self, value, remove=False):
        return ('sdd_session=' + value + '; Path=/; HttpOnly; SameSite=Strict'
                + ('; Secure' if SECURE_COOKIE else '')
                + ('; Max-Age=0' if remove else '; Max-Age=604800'))

    def do_GET(self):
        try:
            if self.path == '/':
                return self.static('index.html', 'text/html; charset=utf-8')
            if self.path == '/app.js':
                return self.static('app.js', 'text/javascript; charset=utf-8')
            if self.path == '/style.css':
                return self.static('style.css', 'text/css; charset=utf-8')
            with connect() as con:
                actor = self.session(con)
                if self.path == '/api/me':
                    return self.respond(200, {'user': actor_public(actor), 'csrf': actor['csrf']})
                if self.path == '/api/data':
                    return self.respond(200, json_data(con, actor['role'], actor['id']))
                if self.path == '/api/users':
                    require_role(actor, 'admin')
                    return self.respond(200, {'users': [public_user(r) for r in con.execute('SELECT * FROM users WHERE deleted_at IS NULL ORDER BY name')]})
                if self.path == '/api/audit':
                    require_role(actor, 'admin')
                    rows = con.execute('''SELECT at,actor_email,event,object_type,object_id,before_json,after_json
                                          FROM audit ORDER BY id DESC LIMIT 250''').fetchall()
                    return self.respond(200, {'events': [dump(r) for r in rows]})
                if self.path == '/api/export':
                    require_role(actor, 'admin')
                    data = json_data(con, 'admin')
                    # Include archived customers referenced by past orders: exported backups must restore cleanly.
                    data['clients'].extend(get_client(r) for r in con.execute(
                        'SELECT * FROM clients WHERE deleted_at IS NOT NULL ORDER BY name COLLATE NOCASE'))
                    data['exportedAt'] = now()
                    return self.respond(200, data)
            raise ApiError(404, 'Página não encontrada.')
        except ApiError as exc:
            self.respond(exc.status, {'error': exc.message})
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.log_message('GET error %s', type(exc).__name__)
            self.respond(500, {'error': 'Falha interna. Tente novamente.'})

    def do_POST(self):
        try:
            self.origin_check()
            data = self.json_body()
            with connect() as con:
                if self.path == '/api/login':
                    return self.login(con, data)
                actor = self.session(con)
                self.csrf_check(actor)
                if self.path == '/api/logout':
                    con.execute('DELETE FROM sessions WHERE token_hash=?', (actor['token_hash'],))
                    return self.respond(200, {'ok': True}, self.cookie('', True))
                if self.path == '/api/password':
                    return self.change_password(con, actor, data)
                if self.path == '/api/totp/setup':
                    secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii').strip('=')
                    con.execute('UPDATE users SET totp_pending=? WHERE id=?', (secret, actor['id']))
                    uri = f'otpauth://totp/{urllib.parse.quote("Sabores das Divas:" + actor["email"])}?secret={secret}&issuer=Sabores%20das%20Divas&digits=6&period=30'
                    return self.respond(200, {'secret': secret, 'uri': uri})
                if self.path == '/api/totp/confirm':
                    row = con.execute('SELECT totp_pending FROM users WHERE id=?', (actor['id'],)).fetchone()
                    if not row['totp_pending'] or not verify_totp(row['totp_pending'], data.get('code')):
                        raise ApiError(400, 'Código inválido. Confira o aplicativo autenticador.')
                    con.execute('UPDATE users SET totp_secret=totp_pending,totp_pending=NULL WHERE id=?', (actor['id'],))
                    audit(con, actor, 'ativou_2fa', 'usuario', actor['id'])
                    return self.respond(200, {'ok': True})
                if self.path == '/api/clients':
                    require_role(actor, 'admin', 'operador', 'financeiro')
                    info = parse_client(data, actor=actor)
                    cid = one_id()
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        ensure_unique_client_phone(con, info['phone'])
                        con.execute('''INSERT INTO clients(id,name,location,store,phone,notes,inadimplente,updated_at)
                                       VALUES(:id,:name,:location,:store,:phone,:notes,:inadimplente,:updated_at)''',
                                    {'id': cid, **info, 'updated_at': now()})
                        audit(con, actor, 'criou', 'cliente', cid, after=info)
                    return self.respond(201, {'id': cid})
                if self.path == '/api/products':
                    require_role(actor, 'admin')
                    info = parse_product(data)
                    pid = one_id()
                    with con:
                        con.execute('''INSERT INTO products(id,name,category,price_cents,active,updated_at)
                                       VALUES(:id,:name,:category,:price_cents,:active,:updated_at)''',
                                    {'id': pid, **info, 'updated_at': now()})
                        audit(con, actor, 'criou', 'produto', pid, after=info)
                    return self.respond(201, {'id': pid})
                if self.path == '/api/orders':
                    require_role(actor, 'admin', 'operador', 'financeiro')
                    info = parse_order(con, data)
                    oid = one_id()
                    with con:
                        con.execute('''INSERT INTO orders(id,date,client_id,client_name,location,store,items_json,notes,created_by,created_at,updated_at)
                                       VALUES(:id,:date,:client_id,:client_name,:location,:store,:items_json,:notes,:created_by,:created_at,:updated_at)''',
                                    {'id': oid, **{k:v for k,v in info.items() if k!='total'},
                                     'created_by': actor['id'], 'created_at': now(), 'updated_at': now()})
                        audit(con, actor, 'criou', 'pedido', oid, after={'date': info['date'], 'total': info['total'], 'client_id': info['client_id']})
                    return self.respond(201, {'id': oid})
                if self.path == '/api/payments':
                    require_role(actor, 'admin', 'financeiro')
                    oid = str_field(data.get('orderId'), 'pedido', 100)
                    day = valid_date(data.get('date'))
                    amount = int_field(data.get('amountCents'), 'Valor recebido', 1, 999_999_999)
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        row = con.execute('SELECT * FROM orders WHERE id=?', (oid,)).fetchone()
                        if not row:
                            raise ApiError(404, 'Pedido não encontrado.')
                        if amount > order_due(con, row):
                            raise ApiError(409, 'Valor maior que o saldo devido. Atualize o extrato.')
                        pid = one_id()
                        con.execute('INSERT INTO payments VALUES(?,?,?,?,?,?)', (pid, oid, day, amount, actor['id'], now()))
                        audit(con, actor, 'recebeu', 'pedido', oid, after={'date': day, 'amountCents': amount, 'paymentId': pid})
                    return self.respond(201, {'ok': True})
                if self.path == '/api/payments/bulk':
                    require_role(actor, 'admin', 'financeiro')
                    client_id = str_field(data.get('clientId'), 'cliente', 100)
                    period = data.get('period')
                    if not isinstance(period, str) or not MONTH_PATTERN.fullmatch(period):
                        raise ApiError(400, 'Mês inválido.')
                    day = valid_date(data.get('date'))
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        exists = con.execute('SELECT 1 FROM clients WHERE id=?', (client_id,)).fetchone()
                        if not exists:
                            raise ApiError(404, 'Cliente não encontrado.')
                        rows = con.execute('SELECT * FROM orders WHERE client_id=? AND date LIKE ?', (client_id, period+'%')).fetchall()
                        result = []
                        for row in rows:
                            due = order_due(con, row)
                            if due > 0:
                                pid = one_id()
                                con.execute('INSERT INTO payments VALUES(?,?,?,?,?,?)', (pid, row['id'], day, due, actor['id'], now()))
                                result.append({'orderId': row['id'], 'paymentId': pid, 'amountCents': due})
                        if not result:
                            raise ApiError(409, 'Este cliente não possui pedidos pendentes no mês.')
                        audit(con, actor, 'quitacao_em_lote', 'cliente', client_id, after={'period': period, 'date': day, 'payments': result})
                    return self.respond(201, {'paidOrders': len(result), 'paidCents': sum(x['amountCents'] for x in result)})
                if self.path == '/api/users':
                    require_role(actor, 'admin')
                    email = validate_email(data.get('email'))
                    name = normalized_username(data.get('name'))
                    username = name
                    key = username_key(name)
                    role = data.get('role')
                    if role not in ROLES:
                        raise ApiError(400, 'Perfil inválido.')
                    temp = new_temporary_pin()
                    uid = one_id()
                    try:
                        with con:
                            con.execute('''INSERT INTO users(id,name,email,username,username_key,role,password_hash,active,must_change,created_at)
                                           VALUES(?,?,?,?,?,?,?,1,0,?)''', (uid, name, email, username, key, role, password_hash(temp), now()))
                            audit(con, actor, 'criou', 'usuario', uid, after={'email': email, 'username': username, 'name': name, 'role': role})
                    except sqlite3.IntegrityError as exc:
                        raise ApiError(409, 'E-mail ou nome de usuário já cadastrado.') from exc
                    return self.respond(201, {'id': uid, 'username': username, 'temporaryPassword': temp})
                if self.path.startswith('/api/users/') and self.path.endswith('/reset'):
                    require_role(actor, 'admin')
                    uid = self.path.split('/')[3]
                    if uid == actor['id']:
                        raise ApiError(403, 'Use Minha conta para alterar sua própria senha.')
                    row = con.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
                    if not row or row['deleted_at'] is not None:
                        raise ApiError(404, 'Usuário não encontrado.')
                    temp = new_temporary_pin()
                    with con:
                        con.execute('''UPDATE users SET password_hash=?, must_change=0, totp_secret=NULL,
                                       totp_pending=NULL, auth_version=auth_version+1 WHERE id=?''', (password_hash(temp), uid))
                        con.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
                        audit(con, actor, 'redefiniu_senha', 'usuario', uid, after={'email': row['email']})
                    return self.respond(200, {'temporaryPassword': temp})
                if self.path == '/api/import':
                    require_role(actor, 'admin')
                    return self.import_legacy(con, actor, data)
            raise ApiError(404, 'Operação não encontrada.')
        except ApiError as exc:
            self.respond(exc.status, {'error': exc.message})
        except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError) as exc:
            self.log_message('POST error %s', type(exc).__name__)
            self.respond(500, {'error': 'Falha interna. Nenhuma alteração confirmada deve ser considerada salva.'})

    def do_PATCH(self):
        try:
            self.origin_check()
            data = self.json_body()
            with connect() as con:
                actor = self.session(con)
                self.csrf_check(actor)
                parts = self.path.strip('/').split('/')
                if len(parts) != 3 or parts[0] != 'api':
                    raise ApiError(404, 'Operação não encontrada.')
                entity, object_id = parts[1], parts[2]
                if entity == 'clients':
                    require_role(actor, 'admin', 'operador', 'financeiro')
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        old = con.execute('SELECT * FROM clients WHERE id=?', (object_id,)).fetchone()
                        if not old or old['deleted_at'] is not None:
                            raise ApiError(404, 'Cliente não encontrado.')
                        info = parse_client(data, old, actor)
                        ensure_unique_client_phone(con, info['phone'], object_id, old['phone'])
                        con.execute('''UPDATE clients SET name=:name,location=:location,store=:store,
                                       phone=:phone,notes=:notes,inadimplente=:inadimplente,updated_at=:updated_at WHERE id=:id''',
                                    {'id': object_id, **info, 'updated_at': now()})
                        audit(con, actor, 'editou', 'cliente', object_id, before=get_client(old), after=info)
                    return self.respond(200, {'ok': True})
                if entity == 'products':
                    require_role(actor, 'admin')
                    info = parse_product(data)
                    with con:
                        old = con.execute('SELECT * FROM products WHERE id=?', (object_id,)).fetchone()
                        if not old or old['deleted_at'] is not None:
                            raise ApiError(404, 'Produto não encontrado.')
                        con.execute('''UPDATE products SET name=:name,category=:category,
                                       price_cents=:price_cents,active=:active,updated_at=:updated_at WHERE id=:id''',
                                    {'id': object_id, **info, 'updated_at': now()})
                        audit(con, actor, 'editou', 'produto', object_id, before=get_product(old), after=info)
                    return self.respond(200, {'ok': True})
                if entity == 'orders':
                    require_role(actor, 'admin', 'operador', 'financeiro')
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        old = con.execute('SELECT * FROM orders WHERE id=?', (object_id,)).fetchone()
                        if not old:
                            raise ApiError(404, 'Pedido não encontrado.')
                        check_user_can_edit_order(actor, old, con)
                        if data.get('updatedAt') != old['updated_at']:
                            raise ApiError(409, 'O pedido foi alterado por outra pessoa. Atualize a página.')
                        info = parse_order(con, data, old)
                        paid = con.execute('SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE order_id=?', (object_id,)).fetchone()[0]
                        if info['total'] < paid:
                            raise ApiError(409, 'O total não pode ser menor que o valor já recebido.')
                        # timestamp with microseconds for optimistic concurrency
                        changed_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds')
                        con.execute('''UPDATE orders SET date=:date,items_json=:items_json,notes=:notes,updated_at=:updated_at
                                       WHERE id=:id''', {'id':object_id,'date':info['date'], 'items_json':info['items_json'],
                                                        'notes':info['notes'],'updated_at':changed_at})
                        audit(con, actor, 'editou', 'pedido', object_id,
                              before={'date':old['date'],'items':json.loads(old['items_json']),'notes':old['notes']},
                              after={'date':info['date'],'items':json.loads(info['items_json']),'notes':info['notes']})
                    return self.respond(200, {'ok':True})
                if entity == 'users':
                    require_role(actor, 'admin')
                    old = con.execute('SELECT * FROM users WHERE id=?', (object_id,)).fetchone()
                    if not old or old['deleted_at'] is not None:
                        raise ApiError(404, 'Usuário não encontrado.')
                    name = normalized_username(data.get('name'))
                    username = name
                    key = username_key(name)
                    role, active = data.get('role'), data.get('active')
                    if role not in ROLES or not isinstance(active, bool):
                        raise ApiError(400, 'Perfil ou situação inválidos.')
                    if old['id'] == actor['id'] and (not active or role != 'admin'):
                        raise ApiError(403, 'Não é permitido remover seu próprio acesso de administrador.')
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        if old['role'] == 'admin' and old['active'] and (not active or role != 'admin'):
                            count = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
                            if count <= 1:
                                raise ApiError(403, 'É necessário manter pelo menos um administrador ativo.')
                        try:
                            con.execute('''UPDATE users SET name=?,username=?,username_key=?,role=?,active=?,auth_version=auth_version+1 WHERE id=?''',
                                        (name, username, key, role, int(active), object_id))
                        except sqlite3.IntegrityError as exc:
                            raise ApiError(409, 'Nome de usuário já cadastrado.') from exc
                        con.execute('DELETE FROM sessions WHERE user_id=?', (object_id,))
                        audit(con, actor, 'alterou_acesso', 'usuario', object_id,
                              before={'name':old['name'],'username':old['username'],'role':old['role'],'active':bool(old['active'])},
                              after={'name':name,'username':username,'role':role,'active':active})
                    return self.respond(200, {'ok':True})
            raise ApiError(404, 'Operação não encontrada.')
        except ApiError as exc:
            self.respond(exc.status, {'error':exc.message})
        except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
            self.log_message('PATCH error %s', type(exc).__name__)
            self.respond(500, {'error':'Falha interna. Tente novamente.'})

    def do_DELETE(self):
        try:
            self.origin_check()
            with connect() as con:
                actor=self.session(con); self.csrf_check(actor)
                parts=self.path.strip('/').split('/')
                if len(parts)==3 and parts[:2]==['api','users']:
                    require_role(actor, 'admin')
                    uid = parts[2]
                    if uid == actor['id']:
                        raise ApiError(403, 'Você não pode excluir sua própria conta.')
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        row = con.execute('SELECT * FROM users WHERE id=? AND deleted_at IS NULL', (uid,)).fetchone()
                        if not row:
                            raise ApiError(404, 'Usuário não encontrado.')
                        if row['role'] == 'admin' and row['active']:
                            count = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND deleted_at IS NULL").fetchone()[0]
                            if count <= 1:
                                raise ApiError(403, 'É necessário manter pelo menos um administrador ativo.')
                        # Soft deletion: retain user ID/name for attribution in orders/payments.
                        # Free previous e-mail and username so they can be used by a new account.
                        con.execute('''UPDATE users SET email=?,username=?,username_key=?,active=0,deleted_at=?,
                                       password_hash=?,totp_secret=NULL,totp_pending=NULL,
                                       must_change=0,auth_version=auth_version+1 WHERE id=?''',
                                    (f'deleted-{uid}@deleted.invalid', f'deleted_{uid}', f'deleted_{uid}', now(),
                                     password_hash(secrets.token_urlsafe(40)), uid))
                        con.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
                        audit(con, actor, 'excluiu_usuario', 'usuario', uid,
                              before={'name': row['name'], 'username': row['username'], 'email': row['email'], 'role': row['role']},
                              after={'access': 'revogado', 'orders': 'preservados', 'payments': 'preservados'})
                    return self.respond(200, {'ok': True})
                if len(parts)==3 and parts[:2]==['api','clients']:
                    require_role(actor, 'admin')
                    cid = parts[2]
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        client = con.execute('SELECT * FROM clients WHERE id=? AND deleted_at IS NULL', (cid,)).fetchone()
                        if client is None:
                            raise ApiError(404, 'Cliente não encontrado.')
                        rows = con.execute('SELECT * FROM orders WHERE client_id=?', (cid,)).fetchall()
                        # Do not hide an outstanding debt by removing the customer from the active list.
                        if any(order_due(con, order) > 0 for order in rows):
                            raise ApiError(409, 'Este cliente possui pedidos com saldo pendente. Quite os pedidos antes de excluir o cadastro.')
                        previous = get_client(client)
                        if rows:
                            # Retain referential integrity and paid sales; exclude from new orders and active contacts.
                            con.execute('UPDATE clients SET deleted_at=?, updated_at=? WHERE id=?', (now(), now(), cid))
                            mode = 'arquivado; pedidos e pagamentos preservados'
                        else:
                            # No orders reference this customer: remove the record altogether.
                            con.execute('DELETE FROM clients WHERE id=?', (cid,))
                            mode = 'excluido definitivamente; sem pedidos vinculados'
                        audit(con, actor, 'excluiu', 'cliente', cid,
                              before={'name': previous['name'], 'location': previous['location']},
                              after={'resultado': mode, 'pedidos_preservados': len(rows)})
                    return self.respond(200, {'ok': True, 'historicalOrders': len(rows)})
                if len(parts)==3 and parts[:2]==['api','products']:
                    require_role(actor, 'admin')
                    pid = parts[2]
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        row = con.execute('SELECT * FROM products WHERE id=? AND deleted_at IS NULL', (pid,)).fetchone()
                        if not row:
                            raise ApiError(404, 'Produto não encontrado.')
                        # Arquivamento lógico: o item desaparece do cardápio e de novos pedidos,
                        # mas permanece identificável em pedidos antigos, extratos e backups.
                        con.execute('UPDATE products SET active=0,deleted_at=?,updated_at=? WHERE id=?',
                                    (now(), now(), pid))
                        audit(con, actor, 'excluiu', 'produto', pid, before=get_product(row),
                              after={'archived': True, 'historico': 'preservado'})
                    return self.respond(200, {'ok': True})
                if len(parts)==3 and parts[:2]==['api','orders']:
                    require_role(actor,'admin')
                    oid=parts[2]
                    with con:
                        con.execute('BEGIN IMMEDIATE')
                        row=con.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone()
                        if not row: raise ApiError(404,'Pedido não encontrado.')
                        if con.execute('SELECT 1 FROM payments WHERE order_id=? LIMIT 1',(oid,)).fetchone():
                            raise ApiError(409,'Pedido com pagamento não pode ser excluído.')
                        con.execute('DELETE FROM orders WHERE id=?',(oid,))
                        audit(con,actor,'excluiu','pedido',oid,before={'date':row['date'],'client':row['client_name'],'items':json.loads(row['items_json'])})
                    return self.respond(200,{'ok':True})
                raise ApiError(404,'Operação não encontrada.')
        except ApiError as exc:self.respond(exc.status,{'error':exc.message})
        except (OSError,sqlite3.Error) as exc:
            self.log_message('DELETE error %s',type(exc).__name__)
            self.respond(500,{'error':'Falha interna. Tente novamente.'})

    def login(self, con, d):
        identifier = d.get('identifier', d.get('email', ''))
        password, code = d.get('password', ''), d.get('code', '')
        if not isinstance(identifier, str) or not 3 <= len(identifier.strip()) <= 200 or not isinstance(password, str) or len(password) > 256:
            raise ApiError(401, 'Usuário/e-mail, senha ou código inválidos.')
        identifier = identifier.strip().lower()
        user = con.execute("SELECT * FROM users WHERE deleted_at IS NULL AND (email=? OR username_key=?)",
                           (identifier, username_key(identifier))).fetchone()
        # One lockout budget for both identifiers and across IPs for the same account.
        principal = 'user:' + user['id'] if user else 'unknown:' + hashlib.sha256(identifier.encode()).hexdigest()
        ip_key = 'ip:' + hashlib.sha256(self.client_address[0].encode()).hexdigest()
        moment = int(time.time())
        with con:
            con.execute('DELETE FROM login_attempts WHERE expires<?', (moment,))
            attempts = con.execute('SELECT * FROM login_attempts WHERE principal=?', (principal,)).fetchone()
            ip_attempts = con.execute('SELECT * FROM login_attempts WHERE principal=?', (ip_key,)).fetchone()
            if (attempts and attempts['attempts'] >= 5 and attempts['expires'] > moment) or \
               (ip_attempts and ip_attempts['attempts'] >= 30 and ip_attempts['expires'] > moment):
                raise ApiError(429, 'Muitas tentativas. Aguarde 15 minutos.')
        good = (bool(user) and user['active'] and check_password(password, user['password_hash'])
                and (not user['totp_secret'] or verify_totp(user['totp_secret'], code)))
        if not good:
            with con:
                for key, old in ((principal, attempts), (ip_key, ip_attempts)):
                    count = (old['attempts'] + 1) if old else 1
                    con.execute("INSERT INTO login_attempts(principal,attempts,expires) VALUES(?,?,?) ON CONFLICT(principal) DO UPDATE SET attempts=excluded.attempts,expires=excluded.expires",
                                (key, count, moment + 900))
            raise ApiError(401, 'Usuário/e-mail, senha ou código inválidos.')
        token = secrets.token_urlsafe(40)
        csrf = secrets.token_urlsafe(32)
        with con:
            con.execute('DELETE FROM login_attempts WHERE principal=?', (principal,))
            con.execute('DELETE FROM sessions WHERE expires<?', (moment,))
            con.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',
                        (hashlib.sha256(token.encode()).hexdigest(), user['id'], csrf, user['auth_version'], moment + 7 * 86400))
            audit(con, user, 'entrou', 'usuario', user['id'])
        self.respond(200, {'user': actor_public(user), 'csrf': csrf}, self.cookie(token))

    def change_password(self,con,actor,data):
        old=data.get('oldPassword','')
        new=data.get('newPassword','')
        if not check_password(old,actor['password_hash']):
            raise ApiError(403,'Senha atual incorreta.')
        hashed=validate_new_password(new)
        if hmac.compare_digest(old,new):
            raise ApiError(400,'Escolha uma senha diferente da atual.')
        with con:
            con.execute('''UPDATE users SET password_hash=?,must_change=0,auth_version=auth_version+1 WHERE id=?''',
                        (hashed,actor['id']))
            con.execute('DELETE FROM sessions WHERE user_id=?',(actor['id'],))
            audit(con,actor,'alterou_senha','usuario',actor['id'])
        self.respond(200,{'ok':True},self.cookie('',True))

    def import_legacy(self,con,actor,data):
        """Migração pontual de backup local. Nunca sobrescreve vendas existentes."""
        if data.get('version')!=1 or not isinstance(data.get('clients'),list) or not isinstance(data.get('products'),list) or not isinstance(data.get('orders'),list):
            raise ApiError(400,'Formato de backup incompatível.')
        clients,products,orders=data['clients'],data['products'],data['orders']
        if len(clients)>5000 or len(products)>2000 or len(orders)>20000:
            raise ApiError(400,'Arquivo acima dos limites de importação.')
        with con:
            con.execute('BEGIN IMMEDIATE')
            if con.execute('SELECT COUNT(*) FROM orders').fetchone()[0] or con.execute('SELECT COUNT(*) FROM products').fetchone()[0]:
                raise ApiError(409,'A importação só é permitida antes de registrar pedidos ou produtos no sistema online.')
            validated_clients=[]
            for c in clients:
                # Backups antigos podem conter um telefone ambíguo. Preserva o dado original
                # sem inventar dígitos; novos/alterados cadastros exigem telefone válido.
                try:
                    info = parse_client(c, actor=actor)
                except ApiError as exc:
                    if (exc.status != 400 or not exc.message.startswith('Telefone inválido')
                            or not isinstance(c, dict)):
                        raise
                    original_phone = str_field(c.get('phone', ''), 'telefone', 32, False)
                    info = parse_client({**c, 'phone': ''}, actor=actor)
                    info['phone'] = original_phone
                info['archived'] = bool(c.get('archived', False))
                validated_clients.append((str_field(c.get('id'),'ID do cliente',100),info))
            if len({x[0] for x in validated_clients})!=len(validated_clients):
                raise ApiError(400,'Cadastro de clientes contém IDs repetidos.')
            validated_products=[]
            for p in products:
                validated_products.append((str_field(p.get('id'),'ID do produto',100),parse_product(p)))
            if len({x[0] for x in validated_products})!=len(validated_products):
                raise ApiError(400,'Produtos contêm IDs repetidos.')
            con.execute('DELETE FROM clients')
            for cid,info in validated_clients:
                con.execute('''INSERT INTO clients(id,name,location,store,phone,notes,inadimplente,updated_at,deleted_at)
                               VALUES(:id,:name,:location,:store,:phone,:notes,:inadimplente,:updated_at,:deleted_at)''',
                            {'id':cid,**info,'updated_at':now(),
                             'deleted_at':now() if info['archived'] else None})
            for pid,info in validated_products:
                is_archived = next((bool(p.get('archived')) for p in products if p.get('id') == pid), False)
                con.execute('''INSERT INTO products(id,name,category,price_cents,active,updated_at,deleted_at)
                               VALUES(:id,:name,:category,:price_cents,:active,:updated_at,:deleted_at)''',
                            {'id':pid,**info,'active':0 if is_archived else info['active'],
                             'updated_at':now(), 'deleted_at':now() if is_archived else None})
            client_lookup={cid:info for cid,info in validated_clients}
            product_lookup={pid:info for pid,info in validated_products}
            for o in orders:
                if not isinstance(o,dict) or o.get('clientId') not in client_lookup:
                    raise ApiError(400,'Pedido contém cliente desconhecido.')
                oid=str_field(o.get('id'),'ID do pedido',100)
                day=valid_date(o.get('date'))
                its=o.get('items')
                if not isinstance(its,list) or not 1<=len(its)<=60:
                    raise ApiError(400,'Itens do pedido inválidos.')
                cleaned=[]
                for i in its:
                    if not isinstance(i,dict) or i.get('kind') not in ('menu','extra'):
                        raise ApiError(400,'Item inválido no backup.')
                    pid=i.get('productId') if i['kind']=='menu' else None
                    if pid is not None and pid not in product_lookup:
                        # permite produto excluído historicamente como adicional preservando nome/preço
                        pid=None
                    category=(product_lookup[pid]['category'] if pid else 'Adicional')
                    cleaned.append({'kind':'menu' if pid else 'extra','productId':pid,
                                    'name':str_field(i.get('name'),'nome do item',140), 'category':category,
                                    'qty':int_field(i.get('qty'),'quantidade',1,999),
                                    'priceCents':int_field(i.get('priceCents'),'preço',0,10_000_000)})
                total=sum(i['qty']*i['priceCents'] for i in cleaned)
                if not 1<=total<=999_999_999:raise ApiError(400,'Valor do pedido inválido.')
                ci=client_lookup[o['clientId']]
                stamp=now()
                con.execute('''INSERT INTO orders(id,date,client_id,client_name,location,store,items_json,notes,created_by,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                            (oid,day,o['clientId'],str_field(o.get('clientName',ci['name']),'cliente',100),
                             o.get('location') if o.get('location') in LOCATIONS else ci['location'],
                             str_field(o.get('store',ci['store']),'loja',120,False),json.dumps(cleaned,ensure_ascii=False),
                             str_field(o.get('notes',''),'observação',600,False),actor['id'],stamp,stamp))
                paid=0
                for p in o.get('payments',[]):
                    if not isinstance(p,dict):raise ApiError(400,'Pagamento inválido.')
                    amount=int_field(p.get('amountCents'),'pagamento',1,999_999_999)
                    paid+=amount
                    if paid>total:raise ApiError(400,'Pagamentos excedem o total do pedido.')
                    con.execute('INSERT INTO payments VALUES(?,?,?,?,?,?)',
                                (one_id(),oid,valid_date(p.get('date')),amount,actor['id'],now()))
            audit(con,actor,'importou_backup','base','restauracao',after={'clients':len(clients),'products':len(products),'orders':len(orders)})
        self.respond(200,{'ok':True,'clients':len(clients),'orders':len(orders)})


def bootstrap_admin():
    init_db()
    with connect() as con:
        if con.execute('SELECT COUNT(*) FROM users').fetchone()[0]:
            print('Já existe usuário. Use o gerenciamento de usuários pelo aplicativo.');return
        name=input('Nome do administrador (também será o usuário de login): ').strip()
        email=input('E-mail administrativo: ').strip().lower()
        try:
            name = normalized_username(name)
        except ApiError as exc:
            raise SystemExit(exc.message) from None
        if not EMAIL_PATTERN.fullmatch(email):
            raise SystemExit('E-mail inválido.')
        # A senha só fica visível no primeiro cadastro iniciado pelo .bat do Windows.
        # Os comandos de servidor, recuperação e alteração de senha seguem ocultando a digitação.
        show_initial_password = os.environ.get('SDD_SHOW_BOOTSTRAP_PASSWORD') == '1'
        read_password = input if show_initial_password else getpass.getpass
        if show_initial_password:
            print('Atenção: a senha aparecerá na tela do CMD durante este cadastro inicial.')
        try:
            while True:
                pwd = read_password('Senha administrativa (mín. 4 caracteres): ')
                if not (4 <= len(pwd) <= 256):
                    print('A senha precisa ter de 4 a 256 caracteres. Tente novamente.')
                    continue
                confirmation = read_password('Confirme a senha: ')
                if pwd != confirmation:
                    print('As senhas são diferentes. Nenhuma conta foi criada. Digite e confirme novamente.')
                    continue
                hashed = validate_new_password(pwd)
                with con:
                    username = available_username(con, name)
                    con.execute('''INSERT INTO users(id,name,email,username,username_key,role,password_hash,active,must_change,created_at)
                                   VALUES(?,?,?,?,?,?,?,1,0,?)''',(one_id(),username,email,username,username_key(username),'admin',hashed,now()))
                print('Seu nome de usuário:', username)
                print('Administrador criado. Ative a autenticação em duas etapas em Minha conta após o primeiro login.')
                return
        except (EOFError, KeyboardInterrupt):
            raise SystemExit('Cadastro interrompido. Administrador não criado.') from None


def seed_clients():
    init_db()
    with connect() as con:
        if con.execute('SELECT COUNT(*) FROM clients').fetchone()[0]:
            print('Já existem clientes. Nenhum cadastro sobrescrito.');return
        source=json.loads((ROOT/'clientes_iniciais.json').read_text(encoding='utf8'))
        with con:
            for c in source:
                # Preserva os dados de origem e não transforma o nome concatenado sem autorização.
                raw_phone = c.get('phone', '')
                digits = re.sub(r'\D', '', raw_phone)
                # One source contact has 12 digits without a country code: do not guess it.
                phone_data = raw_phone if len(digits) in (0, 10, 11) or (len(digits) in (12, 13) and digits.startswith('55')) else ''
                info = parse_client({**c, 'phone': phone_data})
                if raw_phone and not phone_data:
                    info['phone'] = raw_phone  # legacy number, kept for manual verification
                con.execute('''INSERT INTO clients(id,name,location,store,phone,notes,inadimplente,updated_at)
                               VALUES(:id,:name,:location,:store,:phone,:notes,:inadimplente,:updated_at)''',
                            {'id':c['id'],**info,'updated_at':now()})
        print(f'{len(source)} clientes iniciais importados. Pedidos e produtos seguem vazios.')


def recover_admin():
    """Apenas acesso ao servidor: recuperação excepcional de administrador e 2FA."""
    init_db()
    email=input('E-mail do administrador a recuperar: ').strip().lower()
    with connect() as con:
        row=con.execute("SELECT * FROM users WHERE email=? AND role='admin' AND active=1",(email,)).fetchone()
        if not row:
            raise SystemExit('Administrador ativo não encontrado.')
        print('Esta operação desativa o segundo fator, troca a senha e encerra todas as sessões dessa conta.')
        if input('Digite RECUPERAR para confirmar: ').strip()!='RECUPERAR':return
        password=getpass.getpass('Nova senha (4+ caracteres): ')
        if password!=getpass.getpass('Confirme a nova senha: '):
            raise SystemExit('Senhas diferentes.')
        hashed=validate_new_password(password)
        with con:
            con.execute('BEGIN IMMEDIATE')
            con.execute('''UPDATE users SET password_hash=?,must_change=0,totp_secret=NULL,totp_pending=NULL,
                           auth_version=auth_version+1 WHERE id=?''',(hashed,row['id']))
            con.execute('DELETE FROM sessions WHERE user_id=?',(row['id'],))
            con.execute('''INSERT INTO audit(at,actor_id,actor_email,event,object_type,object_id)
                           VALUES(?,?,?,?,?,?)''',(now(),'servidor','acesso_servidor','recuperacao_administrativa','usuario',row['id']))
    print('Acesso redefinido. Ative novamente a autenticação em duas etapas após entrar.')


def backup(destination=None):
    init_db()
    backup_dir=Path(destination or os.environ.get('SDD_BACKUP_DIR',str(ROOT/'backups')))
    backup_dir.mkdir(parents=True,exist_ok=True)
    os.chmod(backup_dir,0o700)
    target=backup_dir/('sabores-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.sqlite3')
    with connect() as source, sqlite3.connect(target) as dst:
        source.backup(dst)
        check=dst.execute('PRAGMA integrity_check').fetchone()[0]
        if check!='ok':
            target.unlink(missing_ok=True)
            raise RuntimeError('Backup falhou na verificação de integridade.')
    os.chmod(target,0o600)
    print('Backup:',target)
    return target


def main():
    command=sys.argv[1] if len(sys.argv)>1 else 'serve'
    if command=='serve':
        init_db()
        if SECURE_COOKIE and not ORIGIN.startswith('https://'):
            raise SystemExit('Cookie Secure requer SDD_PUBLIC_ORIGIN=https://... ou desative-o APENAS para teste local.')
        print(f'Aplicação em {HOST}:{PORT}; origem autorizada: {ORIGIN}; HTTPS cookie: {SECURE_COOKIE}',flush=True)
        ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
    elif command=='bootstrap-admin':bootstrap_admin()
    elif command=='seed-clients':seed_clients()
    elif command=='recover-admin':recover_admin()
    elif command=='backup':backup(sys.argv[2] if len(sys.argv)>2 else None)
    elif command=='backup-loop':
        init_db()
        while True:
            backup()
            directory=Path(os.environ.get('SDD_BACKUP_DIR',str(ROOT/'backups')))
            cutoff=time.time()-30*86400
            for file in directory.glob('sabores-*.sqlite3'):
                if file.stat().st_mtime<cutoff:file.unlink()
            time.sleep(86400)
    else:raise SystemExit('Comandos: serve | bootstrap-admin | seed-clients | recover-admin | backup [pasta] | backup-loop')


if __name__=='__main__':main()
