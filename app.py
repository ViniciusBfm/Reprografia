from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, after_this_request, send_from_directory, make_response
import sqlite3
from hashlib import sha256
import secrets
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from datetime import datetime, timedelta
from os.path import basename
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from config import email,senha
from flask_mail import Message, Mail
import string
import random
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

class User(UserMixin):
    def __init__(self, user_id=None, nome=None, identificacao=None, funcao=None, senha=None, email=None):
        self.id = user_id
        self.nome = nome
        self.identificacao = identificacao
        self.funcao = funcao
        self.senha = senha
        self.email = email

# Configuração do Flask-Mail para o Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = email
app.config['MAIL_PASSWORD'] = senha

mail = Mail(app)

senha_hasheada = bcrypt.generate_password_hash(senha).decode('utf-8')


class LoginForm(FlaskForm):
    nome_usuario = StringField('Nome de Usuário', validators=[DataRequired()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')

#FUNÇÕES
# Função para verificar se um usuário com o mesmo nome já existe
def usuario_existe(nome_usuario):
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM usuarios WHERE nome = ?', (nome_usuario,))
    usuario = cursor.fetchone()

    conn.close()

    return usuario is not None

# Função para verificar se um e-mail já está em uso
def email_existe(email):
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
    usuario = cursor.fetchone()

    conn.close()

    return usuario is not None

def enviar_email_senha(email, token):
    # URL para a página de redefinição de senha
    reset_url = url_for('redefinir_senha', token=token, _external=True)

    # Corpo do email com o link de redefinição de senha
    msg = Message('Redefinição de Senha', sender='your-email@example.com', recipients=[email])
    msg.body = f"Olá,\n\nRecebemos uma solicitação para redefinir a senha da sua conta. Para concluir esse processo, " \
               f"por favor clique no link abaixo ou cole-o em seu navegador:\n\n{reset_url}\n\nSe você não solicitou " \
               f"essa alteração, por favor ignore este email.\n\nAtenciosamente,\Equipe de Suporte"

    mail.send(msg)

# Função para obter usuário por nome de usuário
def obter_usuario_por_nome(nome_usuario):
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM usuarios WHERE nome = ?', (nome_usuario,))
    usuario = cursor.fetchone()

    conn.close()

    return usuario

#gerar uma senha aleatória
def gerar_nova_senha():
    caracteres = string.ascii_letters + string.digits
    nova_senha = ''.join(random.choice(caracteres) for _ in range(6))
    return nova_senha

# Função para atualizar a senha no banco de dados
def atualizar_senha(email, nova_senha):
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    # Atualizar a senha do usuário no banco de dados
    cursor.execute('UPDATE usuarios SET senha = ? WHERE email = ?', (nova_senha, email))

    conn.commit()
    conn.close()

#Função de formatar as opções 
def formatar_funcao(funcao):
    # Remover caracteres especiais e converter para minúsculas
    funcao_formatada = funcao.lower().replace("ç", "c").replace("ã", "a").replace("õ", "o").replace(" ", "_")
    return funcao_formatada

def obter_usuario_por_email(email):
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        usuario = cursor.fetchone()
        if usuario:
            return {'id': usuario[0], 'nome': usuario[1], 'email': usuario[5], 'senha': usuario[4]}
        else:
            return None
        
# Função para salvar o token de redefinição de senha no banco de dados
def salvar_token(nome_usuario, token):
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    cursor.execute('INSERT INTO tokens (user_id, token) VALUES (?, ?)', (nome_usuario, token))

    conn.commit()
    conn.close()

# Função para verificar se o token é válido e obter o usuário associado a ele
def obter_usuario_por_token(token):
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM tokens WHERE token = ? AND used = 0', (token,))
    token_salvo = cursor.fetchone()

    if token_salvo:
        user_id = token_salvo[1]
        print(f"ID do usuário encontrado: {user_id}")  # Adicione essa linha para depuração
        cursor.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,))
        usuario = cursor.fetchone()

        conn.close()

        return usuario
    else:
        conn.close()
        return None

#ROTAS
# Rota para a página de login
@app.route("/")
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('pagina_principal'))
    return render_template('login.html')

#Rota para fazer logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    # Desautenticar o usuário
    logout_user()
    flash('Você saiu com sucesso.', 'success')
    
    # Redirecionar para uma página não autenticada após o logout
    @after_this_request
    def add_no_cache(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    return redirect(url_for('login'))

# Rota para o formulário de registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    opcoes_funcao = ["Professor", "Coordenação", "Reprografia", "Admin"]

    if request.method == 'POST':
        nome = request.form['nome'].lower()
        identificacao = request.form['identificacao']
        funcao = request.form['funcao']
        senha = request.form['senha']
        email = request.form['email']

        # Verificar se o nome de usuário já está em uso
        if usuario_existe(nome):
            flash('Nome de usuário já em uso. Escolha outro nome.')
            return render_template('registro.html', opcoes_funcao=opcoes_funcao, valores=request.form)

        # Verificar se o email já está em uso
        if email_existe(email):
            flash('E-mail já em uso. Escolha outro e-mail.')
            return render_template('registro.html', opcoes_funcao=opcoes_funcao, valores=request.form)

        # Verificar se a função fornecida está entre as opções permitidas
        if funcao not in opcoes_funcao:
            flash('Função inválida. Escolha uma função válida.')
            return render_template('registro.html', opcoes_funcao=opcoes_funcao, valores=request.form)

        # Verificar se a senha atende aos critérios
        if len(senha) < 8 or not any(char.isalpha() for char in senha) or not any(char.isdigit() for char in senha):
            flash('Senha inválida. A senha deve ter pelo menos 8 caracteres, conter pelo menos uma letra e pelo menos um número.')
            return render_template('registro.html', opcoes_funcao=opcoes_funcao, valores=request.form)

        # Hash da senha antes de armazenar no banco de dados
        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

        conn = sqlite3.connect('reprografia.db')
        cursor = conn.cursor()

        # Inserir novo usuário no banco de dados
        cursor.execute('INSERT INTO usuarios (nome, identificacao, funcao, senha, email) VALUES (?, ?, ?, ?, ?)',
                       (nome, identificacao, funcao, senha_hash, email))

        conn.commit()
        conn.close()

        # Redirecionar para a página de login após o registro bem-sucedido
        return redirect(url_for('login'))

    return render_template('registro.html', opcoes_funcao=opcoes_funcao)

# Rota para solicitar redefinição de senha
@app.route('/esqueci_minha_senha', methods=['GET', 'POST'])
def esqueci_minha_senha():
    if request.method == 'POST':
        email = request.form['email']

        # Verificar se o e-mail existe na base de dados
        usuario = obter_usuario_por_email(email)

        if usuario:
            # Gerar um token seguro
            token = secrets.token_urlsafe(32)

            # Salvar o token no banco de dados
            salvar_token(usuario['id'], token)
            
            # Enviar e-mail com o token
            enviar_email_senha(usuario['email'], token)

            flash('Um e-mail foi enviado com instruções para redefinir sua senha.')
            return redirect(url_for('login'))
        else:
            flash('E-mail não encontrado. Verifique o e-mail e tente novamente.')

    return render_template('esqueci_minha_senha.html')

# Rota para redefinir a senha após a confirmação
@app.route('/redefinir_senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    # Verificar se o token é válido
    usuario = obter_usuario_por_token(token)
    print(f"usuário redefinido: {usuario}")
    if usuario is None:
        flash('Token inválido ou expirado. Por favor, solicite um novo token.')
        return redirect(url_for('esqueci_minha_senha'))

    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if nova_senha != confirmar_senha:
            flash('As senhas digitadas não coincidem. Por favor, tente novamente.')
            return render_template('redefinir_senha.html', token=token)

        # Hash da nova senha antes de atualizar no banco de dados
        nova_senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

        # Atualizar a senha do usuário no banco de dados
        atualizar_senha(usuario[5], nova_senha_hash)

        flash('Senha redefinida com sucesso. Você já pode fazer login com sua nova senha.')
        return redirect(url_for('login'))

    return render_template('redefinir_senha.html', token=token)

#Rtota autenticar
@app.route('/autenticar', methods=['POST'])
def autenticar():
    nome_usuario = request.form['nome_usuario'].lower()
    senha = request.form['senha']

    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    # Buscar usuário pelo nome de usuário
    cursor.execute('SELECT * FROM usuarios WHERE nome = ?', (nome_usuario,))
    usuario = cursor.fetchone()

    conn.close()

    if usuario and bcrypt.check_password_hash(usuario[4], senha):
        # A senha fornecida pelo usuário é válida
        session['funcao'] = usuario[3]
        user = User()
        user.id = usuario[0]  # O ID do usuário no banco de dados
        login_user(user)
        return redirect(url_for('pagina_principal'))
    else:
        # A senha fornecida pelo usuário é inválida
        return render_template('login.html', erro_login='Usuário ou senha incorretos')

#Rota processar solicitação
@app.route('/processar_solicitacao', methods=['POST'])
def processar_solicitacao():
    if current_user.is_authenticated:
        conn = sqlite3.connect('reprografia.db')
        cursor = conn.cursor()

    try:
        # Obtenha os dados do formulário
        num_paginas = int(request.form.get('numPaginas'))
        num_copias = int(request.form.get('numCopias'))
        num_total = num_paginas * num_copias
        sala = request.form.get('sala')
        cor = request.form.get('cor')
        data2 = request.form.get('data')
        data3 = datetime.fromisoformat(data2)
        data = data3.strftime("%d/%m/%Y %H:%M:%S")
        arquivo = request.files['arquivo']

        nome_usuario = current_user.nome
        atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        # Adicione este trecho de código antes da inserção no banco de dados
        app.logger.debug(f"Data atual antes da inserção: {atual}")


        # Adicione a verificação da função do usuário
        if current_user.funcao:
            with sqlite3.connect('reprografia.db') as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO solicitacoes (num_paginas, num_copias, num_total, sala, cor, data, nome_usuario, atual, arquivo, extensao, funcao_usuario, id_usuario)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (num_paginas, num_copias, num_total, sala, cor, data, nome_usuario, atual, sqlite3.Binary(arquivo.read()), arquivo.filename.split('.')[-1], current_user.funcao, current_user.id))
        else:
            return redirect(url_for('pagina_principal'))
        return redirect(url_for('pagina_principal'))
    except Exception as e:
        # Lide com exceções (por exemplo, log, exiba mensagem de erro, etc.)
        return f"Erro ao processar a solicitação: {str(e)}"
    finally:
        conn.close()

#Rota para download
@app.route('/download-arquivo/<int:solicitacao_id>')
def download_arquivo(solicitacao_id):
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT arquivo, extensao FROM solicitacoes WHERE id = ?', (solicitacao_id,))
        dados_arquivo, extensao = cursor.fetchone()

    # Gere um nome de arquivo exclusivo para o download
    nome_download = f"arquivo_{solicitacao_id}.{extensao}"

    # Crie uma resposta para enviar o arquivo como anexo para download
    resposta = make_response(dados_arquivo)
    resposta.headers['Content-Type'] = f'application/{extensao}'
    resposta.headers['Content-Disposition'] = f'attachment; filename={nome_download}'

    return resposta

#Rota de excluir arquivos de solicitações
@app.route('/excluir-solicitacao/<int:solicitacao_id>', methods=['POST'])
def excluir_solicitacao(solicitacao_id):
    if request.method == 'POST':
        with sqlite3.connect('reprografia.db') as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM solicitacoes WHERE id = ?', (solicitacao_id,))
            conn.commit()

    return redirect(url_for('pagina_principal'))

#Rota de excluir usuarios de solicitações
@app.route('/excluir_usuario/<nome_usuario>', methods=['POST'])
def excluir_usuario(nome_usuario):
    try:
        conn = sqlite3.connect('reprografia.db')
        cursor = conn.cursor()

        # Remover usuário do banco de dados
        cursor.execute('DELETE FROM usuarios WHERE nome = ?', (nome_usuario,))

        conn.commit()
        conn.close()

        flash(f'Usuário {nome_usuario} removido com sucesso.')
    except Exception as e:
        flash(f'Erro ao remover usuário: {str(e)}')

    return redirect(url_for('pagina_principal'))

#Rota de aprovar solicitação
@app.route('/aprovar_solicitacao/<int:solicitacao_id>', methods=['POST'])
@login_required
def aprovar_solicitacao(solicitacao_id):
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE solicitacoes SET status = "aprovado", usuario_aprovador_id = ?, nome_usuario_aprovador = ? WHERE id = ?', (current_user.id, current_user.nome, solicitacao_id))
        conn.commit()
        return redirect(url_for('pagina_principal'))

# Rota para confirmar impressão
@app.route('/confirmar_impressao/<int:solicitacao_id>', methods=['POST'])
@login_required
def confirmar_impressao(solicitacao_id):
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE solicitacoes SET confirmar = "impresso" WHERE id = ?', (solicitacao_id,))
        conn.commit()
    return redirect(url_for('pagina_principal'))

#Gerar relatorio de todas as solicitações 
@app.route('/gerar_pdf', methods=['GET'])
def gerar_pdf():
    # Configurações do PDF
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter)

    # Organizar dados em uma tabela
    data = [['Data da solicitação', 'Numero total de impressões', 'Setor', 'Usuário']]
    
    # Recuperar as solicitações do banco de dados
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" ORDER BY atual DESC')
        solicitacoes = cursor.fetchall()

    # Adicionar dados da solicitação à tabela
    for solicitacao in solicitacoes:
        data.append([solicitacao[8], solicitacao[3], solicitacao[4], solicitacao[7]])

    # Calcular o somatório da coluna "Numero total"
    somatorio_numero_total = sum(solicitacao[3] for solicitacao in solicitacoes)

    # Adicionar uma linha com o somatório ao final dos dados
    data.append(['Total', somatorio_numero_total, '', ''])

    # Criar a tabela
    table = Table(data, colWidths=[2.0*inch, 2.0*inch, 2.0*inch, 1.0*inch])  # Ajuste as larguras conforme necessário
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5eaef')),  # Cor do título
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 1), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, 0), 6),  # Padding no topo
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),  # Padding na parte inferior
    ]))

     # Criar um estilo para o título
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12,
        alignment=1  # 0 para esquerda, 1 para centro, 2 para direita
    )

    # Adicionar o título ao PDF
    title = Paragraph('Relatório Geral', title_style)
    pdf.build([title, table])  # Adicione o título antes da tabela

    buffer.seek(0)

    # Crie uma resposta Flask com o PDF
    response = make_response(buffer.read())
    response.mimetype = 'application/pdf'
    
    # Defina o nome do arquivo PDF
    response.headers['Content-Disposition'] = 'inline; filename=relatorio_solicitacoes.pdf'

    return response

#Gerar relatorio - USUARIOS
@app.route('/gerar_pdf_usuario', methods=['GET'])
def gerar_pdf_usuario():
    # Configurações do PDF
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter)

    # Organizar dados em uma tabela
    data = [['Data da solicitação', 'Numero total de impressões', 'Setor', 'Usuário']]
    
    # Recuperar as solicitações do banco de dados
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" ORDER BY nome_usuario ASC')
        solicitacoes = cursor.fetchall()

    # Adicionar dados da solicitação à tabela
    for solicitacao in solicitacoes:
        data.append([solicitacao[8], solicitacao[3], solicitacao[4], solicitacao[7]])

    # Calcular o somatório da coluna "Numero total"
    somatorio_numero_total = sum(solicitacao[3] for solicitacao in solicitacoes)

    # Adicionar uma linha com o somatório ao final dos dados
    data.append(['Total', somatorio_numero_total, '', ''])

    # Criar a tabela
    table = Table(data, colWidths=[2.0*inch, 2.0*inch, 2.0*inch, 1.0*inch])  # Ajuste as larguras conforme necessário
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5eaef')),  # Cor do título
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 1), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, 0), 6),  # Padding no topo
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),  # Padding na parte inferior
    ]))

     # Criar um estilo para o título
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12,
        alignment=1  # 0 para esquerda, 1 para centro, 2 para direita
    )

    # Adicionar o título ao PDF
    title = Paragraph('Relatório Geral - Usuários', title_style)
    pdf.build([title, table])  # Adicione o título antes da tabela

    buffer.seek(0)

    # Crie uma resposta Flask com o PDF
    response = make_response(buffer.read())
    response.mimetype = 'application/pdf'
    
    # Defina o nome do arquivo PDF
    response.headers['Content-Disposition'] = 'inline; filename=relatorio_solicitacoes.pdf'

    return response

#Gerar relatorio - SALA
@app.route('/gerar_pdf_setor', methods=['GET'])
def gerar_pdf_setor():
    # Configurações do PDF
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter)

    # Organizar dados em uma tabela
    data = [['Data da solicitação', 'Numero total de impressões', 'Setor', 'Usuário']]
    
    # Recuperar as solicitações do banco de dados
    with sqlite3.connect('reprografia.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" ORDER BY sala ASC')
        solicitacoes = cursor.fetchall()

    # Adicionar dados da solicitação à tabela
    for solicitacao in solicitacoes:
        data.append([solicitacao[8], solicitacao[3], solicitacao[4], solicitacao[7]])

    # Calcular o somatório da coluna "Numero total"
    somatorio_numero_total = sum(solicitacao[3] for solicitacao in solicitacoes)

    # Adicionar uma linha com o somatório ao final dos dados
    data.append(['Total', somatorio_numero_total, '', ''])

    # Criar a tabela
    table = Table(data, colWidths=[2.0*inch, 2.0*inch, 2.0*inch, 1.0*inch])  # Ajuste as larguras conforme necessário
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5eaef')),  # Cor do título
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 1), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, 0), 6),  # Padding no topo
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),  # Padding na parte inferior
    ]))

     # Criar um estilo para o título
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12,
        alignment=1  # 0 para esquerda, 1 para centro, 2 para direita
    )

    # Adicionar o título ao PDF
    title = Paragraph('Relatório Geral - Setor', title_style)
    pdf.build([title, table])  # Adicione o título antes da tabela

    buffer.seek(0)

    # Crie uma resposta Flask com o PDF
    response = make_response(buffer.read())
    response.mimetype = 'application/pdf'
    
    # Defina o nome do arquivo PDF
    response.headers['Content-Disposition'] = 'inline; filename=relatorio_solicitacoes.pdf'

    return response

#Rota de alterar nome
@app.route('/alterar_nome/<int:usuario_id>', methods=['POST'])
def alterar_nome(usuario_id):
    novo_nome = request.form['novo_nome'].lower()

    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    # Atualizar nome do usuário no banco de dados
    cursor.execute('UPDATE usuarios SET nome = ? WHERE id = ?', (novo_nome, usuario_id))

    conn.commit()
    conn.close()

    return redirect(url_for('pagina_principal'))

#Rota para alterar função
@app.route('/alterar_funcao/<int:usuario_id>', methods=['POST'])
def alterar_funcao(usuario_id):
    try:
        nova_funcao = request.json['nova_funcao']

        conn = sqlite3.connect('reprografia.db')
        cursor = conn.cursor()

        # Atualizar a função do usuário no banco de dados
        cursor.execute('UPDATE usuarios SET funcao = ? WHERE id = ?', (nova_funcao, usuario_id))

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Função alterada com sucesso.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Rota para a página principal após autenticação
@app.route('/pagina_principal', methods=['GET', 'POST', 'DELETE'])
@app.route('/pagina_nao_autenticada', methods=['GET', 'POST', 'DELETE'])
@login_required
def pagina_principal():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    funcao_do_usuario_simples = current_user.funcao
    funcao_do_usuario = formatar_funcao(funcao_do_usuario_simples)
    sala_opcao = ['Toddler', 'Nursey', 'Sk', 'Jk', 'Year 1', 'Year 2', 'Year 3', 'Year 4', 'Administrativo', 'Pedagogico']
    opcoes_funcao = ["Professor", "Coordenação", "Admin", "Reprografia"]

    cor_opcao = ['Preto e Branco', 'Colorido']

    if funcao_do_usuario:
        with sqlite3.connect('reprografia.db') as conn:
            cursor = conn.cursor()
            nome_usuario = current_user.nome

            if funcao_do_usuario == 'professor':
                nome_usuario = current_user.nome
                #Apenas as suas solicitações
                cursor.execute('SELECT * FROM solicitacoes WHERE id_usuario = ? ORDER BY atual DESC', (current_user.id,))
                solicitacoes = cursor.fetchall()
                #Suas solicitações aprovadas
                cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" AND id_usuario = ? ORDER BY atual DESC', (current_user.id,))
                solicitacoes_aprovadas_usuario = cursor.fetchall()
                #Suas solicitações aguardando aprovacao
                cursor.execute('SELECT * FROM solicitacoes WHERE status = "pendente" AND id_usuario = ? ORDER BY atual DESC', (current_user.id,))
                solicitacoes_aguardando_usuario = cursor.fetchall()
                # CONTAR solicitações
                # Contar o número total de solicitações aprovadas
                cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "aprovado" AND id_usuario = ? ORDER BY atual DESC', (current_user.id,))
                total_solicitacoes_aprovadas = cursor.fetchone()[0]
                # Contar o número total de solicitações aprovadas
                cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "pendente" AND id_usuario = ? ORDER BY atual DESC', (current_user.id,))
                total_solicitacoes_pendente = cursor.fetchone()[0]
                #Contar todas as solicitações
                total_solicitacoes = total_solicitacoes_aprovadas + total_solicitacoes_pendente

                return render_template('professor_pagina_principal.html', sala_opcao=sala_opcao, cor_opcao=cor_opcao, 
                                       solicitacoes=solicitacoes, solicitacoes_aprovadas_usuario=solicitacoes_aprovadas_usuario, 
                                       solicitacoes_aguardando_usuario=solicitacoes_aguardando_usuario, nome_usuario=nome_usuario, 
                                       total_solicitacoes=total_solicitacoes,total_solicitacoes_aprovadas=total_solicitacoes_aprovadas,
                                        total_solicitacoes_pendente= total_solicitacoes_pendente)

            elif funcao_do_usuario in ['coordenacao', 'admin', 'reprografia']:
                #Solicitação todas
                cursor.execute('SELECT * FROM solicitacoes ORDER BY atual DESC')
                solicitacoes = cursor.fetchall()

                if funcao_do_usuario == 'coordenacao':
                    nome_usuario = current_user.nome
                   # Solicitações aprovadas - TODOS
                    cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" ORDER BY atual DESC')
                    solicitacoes_aprovadas = cursor.fetchall()
                    # Solicitações pendetes - TODOS
                    cursor.execute('SELECT * FROM solicitacoes WHERE status = "pendente" ORDER BY atual DESC')
                    solicitacoes_aguardando = cursor.fetchall()
                    # CONTAR solicitações
                    # Contar todas as solicitações
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes ORDER BY atual DESC')
                    result = cursor.fetchone()

                    if result is not None:
                        total_solicitacoes = result[0]
                    else:
                        total_solicitacoes = 0
                    # Contar o número total de solicitações aprovadas
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "aprovado"')
                    total_solicitacoes_aprovadas = cursor.fetchone()[0]
                    # Contar o número total de solicitações aprovadas
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "pendente"')
                    total_solicitacoes_pendente = cursor.fetchone()[0]
                    return render_template('coordenacao_pagina_principal.html', solicitacoes=solicitacoes, sala_opcao=sala_opcao, 
                                           cor_opcao=cor_opcao, solicitacoes_aprovadas=solicitacoes_aprovadas, nome_usuario=nome_usuario,
                                           total_solicitacoes_aprovadas=total_solicitacoes_aprovadas, total_solicitacoes=total_solicitacoes,
                                           solicitacoes_aguardando=solicitacoes_aguardando ,total_solicitacoes_pendente=total_solicitacoes_pendente)
                             

                elif funcao_do_usuario == 'reprografia':
                    nome_usuario = current_user.nome
                    #Solicitações aprovadas
                    cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" ORDER BY atual DESC')
                    solicitacoes_aprovadas = cursor.fetchall()
                     # Contar o número total de solicitações aprovadas
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "aprovado"')
                    total_solicitacoes_aprovadas = cursor.fetchone()[0]
                    return render_template('reprografia_pagina_principal.html', solicitacoes=solicitacoes, sala_opcao=sala_opcao, 
                                           cor_opcao=cor_opcao, solicitacoes_aprovadas=solicitacoes_aprovadas, nome_usuario=nome_usuario,
                                           total_solicitacoes_aprovadas=total_solicitacoes_aprovadas)

                
                elif funcao_do_usuario == 'admin':
                    nome_usuario = current_user.nome
                    # Todos os usuários
                    cursor.execute('SELECT * FROM usuarios ORDER BY nome ASC')
                    usuarios = cursor.fetchall()

                    # Solicitações aprovadas - TODOS
                    cursor.execute('SELECT * FROM solicitacoes WHERE status = "aprovado" ORDER BY atual DESC')
                    solicitacoes_aprovadas = cursor.fetchall()
                    # Solicitações pendetes - TODOS
                    cursor.execute('SELECT * FROM solicitacoes WHERE status = "pendente" ORDER BY atual DESC')
                    solicitacoes_aguardando = cursor.fetchall()
                    # CONTAR solicitações
                    # Contar todas as solicitações
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes ORDER BY atual DESC')
                    result = cursor.fetchone()

                    if result is not None:
                        total_solicitacoes = result[0]
                    else:
                        total_solicitacoes = 0

                    # Contar o número total de solicitações aprovadas
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "aprovado"')
                    total_solicitacoes_aprovadas = cursor.fetchone()[0]
                    # Contar o número total de solicitações aprovadas
                    cursor.execute('SELECT COUNT(*) FROM solicitacoes WHERE status = "pendente"')
                    total_solicitacoes_pendente = cursor.fetchone()[0]

                    return render_template('admin_pagina_principal.html', solicitacoes=solicitacoes, sala_opcao=sala_opcao,
                                        cor_opcao=cor_opcao, usuarios=usuarios, nome_usuario=nome_usuario,
                                        solicitacoes_aprovadas=solicitacoes_aprovadas, solicitacoes_aguardando=solicitacoes_aguardando,
                                        total_solicitacoes_aprovadas=total_solicitacoes_aprovadas, total_solicitacoes=total_solicitacoes, 
                                        total_solicitacoes_pendente=total_solicitacoes_pendente, funcao_do_usuario=funcao_do_usuario, opcoes_funcao=opcoes_funcao)



    return redirect(url_for('login'))

#OUTRAS REQUISIÇÕES
@app.template_filter('get_filename')
def get_filename(path):
    return basename(path)

@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@login_manager.user_loader
def load_user(user_id):
    # Lógica para carregar os dados do banco de dados usando o user_id
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()

    conn.close()

    if user_data:
        # Criar uma instância de User diretamente com os dados do banco de dados
        user = User(user_id=user_data[0], nome=user_data[1], identificacao=user_data[2], funcao=user_data[3], senha=user_data[4], email=user_data[5])
        return user
    else:
        return None

#Impedir Acesso Direto pela Barra de Endereços
@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('Você precisa fazer login para acessar esta página.', 'warning')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Criar tabela de usuários se não existir
    conn = sqlite3.connect('reprografia.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            identificacao TEXT UNIQUE NOT NULL,
            funcao TEXT NOT NULL,
            senha TEXT NOT NULL,
            email TEXT
        );
    ''')
    # Criar tabela de tokens de redefinição de senha se não existir
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id)
        );
    ''')


    # Criar tabela de solicitações para impressão
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solicitacoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            num_paginas INTEGER NOT NULL,
            num_copias INTEGER NOT NULL,
            num_total INTEGER NOT NULL,
            sala TEXT NOT NULL,
            cor TEXT,
            data DATETIME NOT NULL,
            nome_usuario TEXT NOT NULL,
            atual DATETIME NOT NULL,
            arquivo BLOB,
            extensao TEXT,
            funcao_usuario TEXT NOT NULL,
            id_usuario INTEGER NOT NULL,
            status TEXT DEFAULT 'pendente',
            usuario_aprovador_id INTEGER,
            nome_usuario_aprovador TEXT,
            confirmar TEXT DEFAULT 'Não impresso',
            FOREIGN KEY (id_usuario) REFERENCES usuarios(id),
            FOREIGN KEY (usuario_aprovador_id) REFERENCES usuarios(id)
            
        );
    ''')

    conn.commit()
    conn.close()

    app.run(debug=True)
