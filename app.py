from flask import Flask, render_template, request, redirect, url_for, flash
from blind_utils import (
    load_keys,
    # Reemplazamos la función anterior:
    message_to_int_with_nonce, generate_nonce,
    generate_blinding_factor, blind_message,
    sign_blinded, unblind_signature,
    verify_signature, record_vote
)
import json
from collections import Counter

app = Flask(__name__)
app.secret_key = 'una_clave_secreta_para_flashes'

# Cargar claves RSA
priv_key, pub_key = load_keys()

# 1. Página principal: elegir candidato
@app.route('/')
def index():
    candidatos = ['Candidato A', 'Candidato B', 'Candidato C']
    try:
        with open('votes.json', 'r') as f:
            votos = json.load(f)
        conteo = Counter(v['candidato'] for v in votos)
    except Exception:
        conteo = {c: 0 for c in candidatos}
    resultados = [(c, conteo.get(c, 0)) for c in candidatos]
    return render_template('index.html', candidatos=candidatos, resultados=resultados)

# 2. Solicitar firma cegada
@app.route('/blind_request', methods=['POST'])
def blind_request():
    opcion = request.form.get('opcion')
    if not opcion:
        flash('Debe seleccionar un candidato.', 'error')
        return redirect(url_for('index'))

    # 2.1. Generar nonce
    nonce = generate_nonce()  # bytes

    # 2.2. Calcular m = Hash(candidato || nonce) % N
    m_int = message_to_int_with_nonce(opcion, nonce, pub_key)

    # 2.3. Generar factor de cegado r
    r = generate_blinding_factor(pub_key)

    # 2.4. Calcular mensaje cegado m' = m * r^e mod N
    m_blinded = blind_message(m_int, r, pub_key)

    # 2.5. La autoridad firma cegado: s' = (m_blinded)^d mod N
    s_blinded = sign_blinded(m_blinded, priv_key)

    # 2.6. Enviamos a la plantilla: candidato (para mostrar), 
    #      nonce (bytes), m_int, r, s_blinded
    # Nota: convertimos nonce a hexadecimal para transporte HTML
    nonce_hex = nonce.hex()
    return render_template('blind_request.html',
                           candidato=opcion,
                           nonce_hex=nonce_hex,
                           m=m_int, r=r, s_blinded=s_blinded)

# 3. Destapar y votar
@app.route('/vote', methods=['POST'])
def vote():
    # Recibimos de formulario:
    candidato = request.form.get('candidato')
    nonce_hex = request.form.get('nonce_hex')
    m_int = int(request.form.get('m'))
    r = int(request.form.get('r'))
    s_blinded = int(request.form.get('s_blinded'))

    # Convertimos nonce de hex a bytes
    nonce = bytes.fromhex(nonce_hex)

    # 3.1. Destapar firma cegada: s = s' * r^{-1} mod N
    s = unblind_signature(s_blinded, r, pub_key)

    # 3.2. Verificamos que s^e % N == m
    valido = verify_signature(m_int, s, pub_key)
    if not valido:
        flash('La verificación de la firma ha fallado.', 'error')
        return redirect(url_for('index'))

    # 3.3. Mostrar formulario con: candidato, nonce_hex, m, s
    return render_template('vote.html',
                           candidato=candidato,
                           nonce_hex=nonce_hex,
                           m=m_int, s=s)

# 4. Publicar y guardar el voto
@app.route('/result', methods=['POST'])
def result():
    candidato = request.form.get('candidato')
    nonce_hex = request.form.get('nonce_hex')
    m_int = int(request.form.get('m'))
    s = int(request.form.get('s'))

    # Reconstruimos nonce
    nonce = bytes.fromhex(nonce_hex)

    # 4.1. Verificar nuevamente
    if not verify_signature(m_int, s, pub_key):
        flash('La firma ya no es válida al momento de publicar.', 'error')
        return redirect(url_for('index'))

    # 4.2. Guardar el registro en votes.json
    #     Ahora incluimos también candidato y nonce_hex para contar votos
    record_vote({
        'candidato': candidato,
        'nonce_hex': nonce_hex,
        'm': str(m_int),
        's': str(s)
    })

    flash('¡Voto registrado con éxito!', 'success')
    return render_template('result.html',
                           candidato=candidato,
                           nonce_hex=nonce_hex,
                           m=m_int, s=s)

if __name__ == '__main__':
    app.run(debug=True)
