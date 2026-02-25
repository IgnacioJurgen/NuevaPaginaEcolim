# Ecolim Backend API (Flask)

Backend de la landing page de Ecolim. Recibe formularios de contacto, valida reCAPTCHA v3, y envía notificaciones a Telegram.

## Arquitectura

```
Frontend (index.html)  →  POST /submit  →  Flask API (Koyeb)  →  Telegram Bot
         ↕                                        ↕
   reCAPTCHA v3 token              Google reCAPTCHA verify
```

## Archivos

| Archivo | Función |
|---------|---------|
| `app.py` | Servidor Flask con validaciones y seguridad |
| `requirements.txt` | Dependencias Python |
| `Procfile` | Comando de ejecución (gunicorn) |
| `runtime.txt` | Versión de Python (3.12) |
| `.env.example` | Template de variables de entorno |

## Endpoints

| Método | Ruta | Descripción | Rate Limit |
|--------|------|-------------|------------|
| `GET` | `/` | Health check texto | 200/día |
| `GET` | `/healthz` | Health check JSON | 200/día |
| `POST` | `/submit` | Envío de formulario | 5/min |

---

## 🚀 Deploy en Koyeb (Desde Cero)

### Paso 1: Subir a GitHub
Crea un repositorio en GitHub y sube **solo** los archivos de esta carpeta `python/`:

```
python/
├── app.py
├── requirements.txt
├── Procfile
├── runtime.txt
└── .env.example
```

> ⚠️ **NO subas** archivos `.env` con credenciales reales a GitHub.

### Paso 2: Crear servicio en Koyeb
1. Ve a [app.koyeb.com](https://app.koyeb.com) e inicia sesión
2. Click **"Create Service"**
3. Selecciona **"GitHub"** como fuente
4. Conecta tu repositorio y selecciona la rama (`main`)
5. Si el repo tiene subcarpetas, configura el **Root Directory** como `/` (o la ruta donde están los archivos)

### Paso 3: Configurar Build
- **Builder:** Buildpack (automático)
- **Run command:** Se detecta automáticamente del `Procfile`
- **Port:** `8000` (u otro que Koyeb asigne vía `$PORT`)

### Paso 4: Variables de Entorno
En la sección **"Environment Variables"**, agrega estas 3 variables:

| Variable | Valor |
|----------|-------|
| `RECAPTCHA_SECRET_KEY` | Tu secret key de [Google reCAPTCHA v3](https://www.google.com/recaptcha/admin) |
| `TELEGRAM_BOT_TOKEN` | Token de tu bot de Telegram (vía [@BotFather](https://t.me/BotFather)) |
| `TELEGRAM_CHAT_ID` | El Chat ID donde llegarán los mensajes |

### Paso 5: Deploy
1. Click **"Deploy"**
2. Espera que el build termine (~2-3 minutos)
3. Verifica que el health check pase visitando: `https://tu-servicio.koyeb.app/healthz`
4. Deberías ver: `{"status": "ok"}`

### Paso 6: Actualizar el Frontend
Una vez tengas la URL de Koyeb, actualiza la constante en `index.html`:

```javascript
const API_URL = 'https://tu-nueva-url.koyeb.app/submit';
```

---

## 🧪 Desarrollo Local

```bash
cd python
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores

# Ejecutar
flask run --debug
```

---

## 🔒 Seguridad Implementada

| Capa | Protección |
|------|-----------|
| Security Headers | XSS, clickjacking, HSTS, no-cache |
| Body Limit 16KB | Anti-DoS |
| Content-Type check | Solo form-urlencoded |
| Honeypot server-side | Descarta bots silenciosamente |
| reCAPTCHA v3 score ≥ 0.5 | Filtra bots automáticos |
| Sanitización HTML | Escapa `<script>`, null bytes |
| Whitelist de servicios | Solo 5 servicios válidos |
| Regex teléfono chileno | Solo `9XXXXXXXX` |
| Detección de spam | URLs, scripts, keywords spam |
| IP logging | Auditoría completa |

---

## 📬 Campos del Formulario

El frontend envía vía `POST` con `Content-Type: application/x-www-form-urlencoded`:

| Campo | Tipo | Requerido | Validación |
|-------|------|-----------|------------|
| `nombre` | string | ✅ | 2-100 chars, sin spam |
| `telefono` | string | ✅ | Exactamente 9 dígitos, empieza con 9 |
| `servicio` | string | ✅ | Debe ser uno de los 5 válidos |
| `descripcion` | string | ✅ | 10-1000 chars, sin URLs/spam |
| `correo` | string | ❌ | Formato email válido |
| `g-recaptcha-response` | string | ✅ | Token reCAPTCHA v3 |
| `website` | string | ❌ | Honeypot (debe estar vacío) |
