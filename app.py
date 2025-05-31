from flask import Flask, render_template, request, redirect, url_for, flash
from blind_utils import (
    load_keys,
    message_to_int_with_nonce, generate_nonce,
    generate_blinding_factor, blind_message,
    sign_blinded, unblind_signature,
    verify_signature, record_vote
)
import json
from collections import Counter

app = Flask(__name__)
app.secret_key = 'una_clave_secreta_para_flashes'

priv_key, pub_key = load_keys()

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

@app.route('/blind_request', methods=['POST'])
def blind_request():
    opcion = request.form.get('opcion')
    if not opcion:
        flash('Debe seleccionar un candidato.', 'error')
        return redirect(url_for('index'))

    nonce = generate_nonce()  
    
    m_int = message_to_int_with_nonce(opcion, nonce, pub_key)
    
    r = generate_blinding_factor(pub_key)

    m_blinded = blind_message(m_int, r, pub_key)

    s_blinded = sign_blinded(m_blinded, priv_key)

    nonce_hex = nonce.hex()
    return render_template('blind_request.html',
                           candidato=opcion,
                           nonce_hex=nonce_hex,
                           m=m_int, r=r, s_blinded=s_blinded)

@app.route('/vote', methods=['POST'])
def vote():
    
    candidato = request.form.get('candidato')
    nonce_hex = request.form.get('nonce_hex')
    m_int = int(request.form.get('m'))
    r = int(request.form.get('r'))
    s_blinded = int(request.form.get('s_blinded'))

    nonce = bytes.fromhex(nonce_hex)

    s = unblind_signature(s_blinded, r, pub_key)

    valido = verify_signature(m_int, s, pub_key)
    if not valido:
        flash('La verificación de la firma ha fallado.', 'error')
        return redirect(url_for('index'))

    return render_template('vote.html',
                           candidato=candidato,
                           nonce_hex=nonce_hex,
                           m=m_int, s=s)

@app.route('/result', methods=['POST'])
def result():
    candidato = request.form.get('candidato')
    nonce_hex = request.form.get('nonce_hex')
    m_int = int(request.form.get('m'))
    s = int(request.form.get('s'))

    nonce = bytes.fromhex(nonce_hex)

    if not verify_signature(m_int, s, pub_key):
        flash('La firma ya no es válida al momento de publicar.', 'error')
        return redirect(url_for('index'))

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
