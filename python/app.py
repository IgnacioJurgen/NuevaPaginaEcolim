import re
import html
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import requests
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from werkzeug.middleware.proxy_fix import ProxyFix
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ===================================================================
#  CONFIGURACIÓN BASE
# ===================================================================
app = Flask(__name__)

# Confiar en el proxy para obtener la IP correcta
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Limitar tamaño máximo del body (16 KB — un formulario simple no necesita más)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16 KB

# CORS restringido SOLO a tu dominio (bloquea peticiones desde otros sitios)
CORS(app, resources={
    r"/*": {
        "origins": ["https://ecolim.cl", "https://www.ecolim.cl"],
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type"],
        "max_age": 3600
    }
})

# Rate limiting más agresivo
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ===================================================================
#  SECURITY HEADERS (protección contra XSS, clickjacking, sniffing)
# ===================================================================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # No cachear respuestas de la API
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

# ===================================================================
#  CONSTANTES DE VALIDACIÓN
# ===================================================================

# Servicios válidos (whitelist)
SERVICIOS_VALIDOS = {
    "Desratización",
    "Fumigación",
    "Sanitización",
    "Desinsectación",
    "Control de Aves"
}

# Límites de longitud de campos
CAMPO_LIMITES = {
    'nombre': (2, 100),
    'telefono': (9, 9),
    'descripcion': (10, 1000),
    'servicio': (3, 50),
    'correo': (0, 150)
}

# Regex para detectar spam (URLs, HTML, scripts)
SPAM_PATTERNS = re.compile(
    r'(https?://|www\.|\.com/|\.cl/|\.net/|\.org/|'
    r'<script|javascript:|on\w+\s*=|'
    r'\[url|href\s*=|'
    r'(buy|cheap|viagra|casino|crypto|click here|winner|congratulations))',
    re.IGNORECASE
)

# Regex para validar teléfono chileno (9 dígitos, empieza con 9)
TELEFONO_REGEX = re.compile(r'^9\d{8}$')

# Regex para validar email
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# Regex para detectar caracteres sospechosos (inyección)
INJECTION_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# Umbral mínimo de score reCAPTCHA (0.0 = bot, 1.0 = humano)
RECAPTCHA_SCORE_THRESHOLD = 0.5

# ===================================================================
#  RUTAS BÁSICAS
# ===================================================================

@app.route('/')
def home():
    return 'Bienvenido a la API de Ecolim'

@app.route('/healthz')
def healthz():
    return jsonify({"status": "ok"}), 200

# ===================================================================
#  ERROR HANDLERS
# ===================================================================

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    app.logger.warning(f"Rate limit alcanzado desde IP: {get_remote_address()}")
    return jsonify({"error": "Demasiadas solicitudes, intenta más tarde"}), 429

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "El contenido es demasiado grande"}), 413

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Solicitud inválida"}), 400

# ===================================================================
#  FUNCIONES DE SEGURIDAD
# ===================================================================

def sanitizar_input(texto: str) -> str:
    """Limpia un texto de caracteres peligrosos: HTML entities, control chars."""
    if not texto:
        return ""
    # Eliminar caracteres de control (null bytes, etc.)
    texto = INJECTION_REGEX.sub('', texto)
    # Escapar HTML entities para prevenir XSS
    texto = html.escape(texto, quote=True)
    # Eliminar espacios excesivos
    texto = ' '.join(texto.split())
    return texto.strip()


def validar_longitud(campo: str, valor: str) -> bool:
    """Verifica que un campo esté dentro de los límites permitidos."""
    if campo not in CAMPO_LIMITES:
        return True
    min_len, max_len = CAMPO_LIMITES[campo]
    return min_len <= len(valor) <= max_len


def detectar_spam(texto: str) -> bool:
    """Detecta patrones de spam en el texto. Retorna True si es spam."""
    return bool(SPAM_PATTERNS.search(texto))


def validar_recaptcha(token: str) -> bool:
    """Valida el token reCAPTCHA v3 incluyendo verificación de score."""
    secret_key = os.getenv('RECAPTCHA_SECRET_KEY')
    if not secret_key:
        app.logger.warning("RECAPTCHA_SECRET_KEY no está configurada.")
        return False
    try:
        resp = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': secret_key, 'response': token},
            timeout=10
        ).json()

        success = resp.get('success', False)
        score = resp.get('score', 0.0)
        action = resp.get('action', '')

        # Log para auditoría
        app.logger.info(
            f"reCAPTCHA: success={success}, score={score}, action={action}"
        )

        # Verificar: success + score mínimo + action correcta
        if not success:
            app.logger.warning(f"reCAPTCHA falló: {resp.get('error-codes', [])}")
            return False

        if score < RECAPTCHA_SCORE_THRESHOLD:
            app.logger.warning(
                f"reCAPTCHA score bajo: {score} (umbral: {RECAPTCHA_SCORE_THRESHOLD})"
            )
            return False

        if action != 'submit':
            app.logger.warning(f"reCAPTCHA action inesperada: {action}")
            return False

        return True

    except Exception as e:
        app.logger.error(f"Error validando reCAPTCHA: {e}")
        return False

# ===================================================================
#  TELEGRAM (con reintentos)
# ===================================================================

def enviar_mensaje_telegram(
    nombre: str, telefono: str, servicio: str,
    descripcion: str, correo: str = "", ip: str = ""
):
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    if not token or not chat_id:
        return {"error": "Faltan credenciales de Telegram"}

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    correo_line = f"\n• Correo: {correo}" if correo else ""
    body = (
        "\U0001f4e9 Nuevo cliente (Formulario Ecolim)\n"
        f"• Nombre: {nombre}\n"
        f"• Teléfono: +56{telefono}\n"
        f"• Servicio: {servicio}\n"
        f"• Descripción: {descripcion}"
        f"{correo_line}\n"
        f"─────────────\n"
        f"IP: {ip}"
    )
    payload = {
        "chat_id": chat_id,
        "text": body,
    }

    try:
        session = requests.Session()
        retry = Retry(
            total=3, backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        resp = session.post(url, json=payload, timeout=10)
        app.logger.info(f"Telegram status={resp.status_code}")
        return resp.json()
    except Exception as e:
        app.logger.error(f"Error enviando a Telegram: {e}")
        return {"error": str(e)}

# ===================================================================
#  ENDPOINT DEL FORMULARIO (con validaciones completas)
# ===================================================================

@app.route('/submit', methods=['POST'])
@limiter.limit("5 per minute")
def submit():
    client_ip = get_remote_address()

    # ── 1. Verificar Content-Type ──
    content_type = request.content_type or ''
    if 'application/x-www-form-urlencoded' not in content_type:
        app.logger.warning(f"Content-Type inválido: {content_type} desde IP: {client_ip}")
        return jsonify({'error': 'Tipo de contenido no válido'}), 400

    # ── 2. Honeypot server-side (el campo 'website' debe estar vacío) ──
    honeypot = (request.form.get('website') or '').strip()
    if honeypot:
        app.logger.warning(f"Honeypot activado desde IP: {client_ip}, valor: {honeypot}")
        # Responder 200 para no alertar al bot
        return jsonify({'message': 'Datos enviados exitosamente!'}), 200

    # ── 3. Validar reCAPTCHA (con score) ──
    recaptcha_token = request.form.get('g-recaptcha-response')
    if not recaptcha_token or not validar_recaptcha(recaptcha_token):
        app.logger.warning(f"reCAPTCHA fallido desde IP: {client_ip}")
        return jsonify({'error': 'Error de validación de seguridad'}), 400

    try:
        # ── 4. Extraer y sanitizar campos ──
        nombre = sanitizar_input(request.form.get('nombre') or '')
        telefono = sanitizar_input(request.form.get('telefono') or '')
        descripcion = sanitizar_input(request.form.get('descripcion') or '')
        servicio = sanitizar_input(request.form.get('servicio') or '')
        correo = sanitizar_input(request.form.get('correo') or '')

        # ── 5. Campos obligatorios presentes ──
        if not all([nombre, telefono, descripcion, servicio]):
            return jsonify({'error': 'Todos los campos obligatorios deben estar llenos'}), 400

        # ── 6. Validar longitudes ──
        for campo, valor in [
            ('nombre', nombre), ('telefono', telefono),
            ('descripcion', descripcion), ('servicio', servicio),
            ('correo', correo)
        ]:
            if not validar_longitud(campo, valor):
                min_l, max_l = CAMPO_LIMITES[campo]
                app.logger.warning(
                    f"Campo '{campo}' fuera de límites (len={len(valor)}) desde IP: {client_ip}"
                )
                return jsonify({
                    'error': f'El campo {campo} debe tener entre {min_l} y {max_l} caracteres'
                }), 400

        # ── 7. Validar teléfono chileno ──
        if not TELEFONO_REGEX.match(telefono):
            return jsonify({'error': 'El teléfono debe ser un número chileno válido (9 dígitos, ej: 912345678)'}), 400

        # ── 8. Validar servicio contra whitelist ──
        if servicio not in SERVICIOS_VALIDOS:
            app.logger.warning(
                f"Servicio inválido: '{servicio}' desde IP: {client_ip}"
            )
            return jsonify({'error': 'Servicio no válido'}), 400

        # ── 9. Validar email si se proporcionó ──
        if correo and not EMAIL_REGEX.match(correo):
            return jsonify({'error': 'El correo electrónico no es válido'}), 400

        # ── 10. Detectar spam en nombre y descripción ──
        for campo, valor in [('nombre', nombre), ('descripcion', descripcion)]:
            if detectar_spam(valor):
                app.logger.warning(
                    f"SPAM detectado en '{campo}' desde IP: {client_ip}: {valor[:100]}"
                )
                return jsonify({
                    'error': 'Se detectó contenido no permitido. No incluyas enlaces ni caracteres sospechosos.'
                }), 400

        # ── 11. Todo validado → Enviar a Telegram ──
        app.logger.info(
            f"Formulario válido de {nombre} ({telefono}) - Servicio: {servicio} - IP: {client_ip}"
        )
        enviar_mensaje_telegram(nombre, telefono, servicio, descripcion, correo, client_ip)

        return jsonify({'message': 'Datos enviados exitosamente!'}), 200

    except Exception as e:
        app.logger.error(f"Error al procesar formulario desde IP {client_ip}: {e}")
        return jsonify({'error': 'Ocurrió un error interno'}), 500
