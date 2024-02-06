import sqlite3

def remover_usuario(nome_usuario):
    try:
        conn = sqlite3.connect('reprografia.db')
        cursor = conn.cursor()

        # Remover usuário do banco de dados
        cursor.execute('DELETE FROM usuarios WHERE nome = ?', (nome_usuario,))

        conn.commit()
        conn.close()

        print(f'Usuario {nome_usuario} removido com sucesso.')
    except Exception as e:
        print(f'Erro ao remover usuário: {str(e)}')

if __name__ == '__main__':
    nome_usuario_a_remover = 'vbfmendes'
    
    remover_usuario(nome_usuario_a_remover)
