import sqlite3
from hashlib import sha256

def adicionar_usuario(nome, identificacao, funcao, senha):
    # Hash da senha antes de armazenar no banco de dados
    senha_hash = sha256(senha.encode()).hexdigest()

    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    # Inserir novo usuário no banco de dados com a função como argumento
    cursor.execute('INSERT INTO usuarios (nome, identificacao, funcao, senha) VALUES (?, ?, ?, ?)',
                (nome, identificacao, funcao, senha_hash))

    conn.commit()
    conn.close()

# Adicionar o usuário
adicionar_usuario('vinicius', '1', 'admin', '1')
print('Usuario adicionado!')
