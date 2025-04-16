import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.utils import secure_filename
import pytz
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from functools import wraps
from flask import abort
from flask_wtf import FlaskForm
from flask_migrate import Migrate
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from flask import render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
import re  # Para validar a senha
from werkzeug.security import generate_password_hash, check_password_hash

from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, flash, redirect, url_for


# Obtendo o horário atual no fuso horário UTC
utc_now = datetime.now(pytz.utc)

# Convertendo para o fuso horário de Brasília
brasilia_tz = pytz.timezone('America/Sao_Paulo')
brasilia_time = utc_now.astimezone(brasilia_tz)

# Formatando a data e hora para exibição
formatted_time = brasilia_time.strftime('%d/%m/%Y %H:%M:%S')


# Criação do objeto Flask
app = Flask(__name__)
bcrypt = Bcrypt(app)  # Inicializa o Bcrypt


app.config['SECRET_KEY'] = os.urandom(24)  # Gera uma chave secreta aleatória de 24 bytes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///petshop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

migrate = Migrate(app, db)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Inicializando o banco de dados

# Continue com a definição dos modelos e rotas


with app.app_context():
    db.create_all() 


# Definindo o modelo de usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='cliente')
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))  # Relacionamento com Cliente
    cliente = db.relationship('Cliente', back_populates='usuario', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"



    
# Função para carregar o usuário pelo ID (usada pelo Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Função para verificar o papel do usuário
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)  # Acesso negado
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Validação de senha com mensagem personalizada
def validate_password(form, field):
    password = field.data
    if len(password) < 6:
        raise ValidationError('A senha deve ter pelo menos 6 caracteres.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('A senha deve conter pelo menos uma letra maiúscula.')
    if not re.search(r'\d', password):
        raise ValidationError('A senha deve conter pelo menos um número.')
    if not re.search(r'[!@#\$%\^&\*]', password):
        raise ValidationError('A senha deve conter pelo menos um caractere especial (!, @, #, $, etc.).')
    
class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(message="O nome de usuário é obrigatório."), 
                                      Length(min=3, max=20, message="O nome de usuário deve ter entre 3 e 20 caracteres.")])
    
    email = StringField('Email', 
                        validators=[DataRequired(message="O email é obrigatório."), 
                                    Email(message="Digite um email válido.")])
    
    password = PasswordField('Password', 
                             validators=[DataRequired(message="A senha é obrigatória."),
                                        validate_password])
    
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(message="A confirmação da senha é obrigatória."),
                                                EqualTo('password', message="As senhas devem ser iguais.")])
    
    role = SelectField('Role', 
                       choices=[('cliente', 'Cliente'), ('prestador', 'Prestador de Serviços')],
                       validators=[DataRequired(message="Escolha um papel.")])
    
    telefone = StringField('Telefone', 
                           validators=[Optional(), Length(min=10, max=15, message="O telefone deve ter entre 10 e 15 caracteres.")])

    submit = SubmitField('Sign Up')

    # Validação se o email já está em uso
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este email já está em uso. Escolha outro.')

    # Validação se o nome de usuário já está em uso
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nome de usuário já está em uso. Escolha outro.')

        
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Redireciona se o usuário já estiver autenticado
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Verificar se o email já está em uso
        user_email = User.query.filter_by(email=form.email.data).first()

        if user_email:
           
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            # Atualizar as informações do cliente associado, se aplicável
            cliente = Cliente.query.get(user_email.cliente_id)
            if cliente:
                cliente.nome = form.username.data
                cliente.email = form.email.data
                cliente.telefone = form.telefone.data
                db.session.commit() 
            
            # Atualizar o usuário
            user_email.username = form.username.data
            user_email.password = hashed_password 
            user_email.role = form.role.data  
            db.session.commit()  

            flash('Seu cadastro foi atualizado com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login')) 
        
        else:
            
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            # Criar novo cliente
            cliente = Cliente(nome=form.username.data, email=form.email.data, telefone=form.telefone.data)
            db.session.add(cliente)
            db.session.commit()  

            # Criar novo usuário com as informações do formulário
            user = User(username=form.username.data, email=form.email.data, password=hashed_password, 
                        role=form.role.data, cliente_id=cliente.id)
            db.session.add(user)
            db.session.commit()

            flash('Sua conta foi criada com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login'))  # Redireciona para a página de login
    
    return render_template('register.html', form=form)





@app.route("/recadastrar", methods=['GET', 'POST'])
def recadastrar():
    # Pega o email e o nome passados pela URL
    email = request.args.get('email')
    nome = request.args.get('nome')

    print(f"Email: {email}, Nome: {nome}")  # Log para depuração

    # Verifica se o email está sendo passado
    if not email:
        flash('Email não fornecido. Tente novamente.', 'danger')
        return redirect(url_for('esqueci_senha'))

    # Verifica se o usuário existe com base no email
    user = User.query.filter_by(email=email).first()

    # Se o usuário não for encontrado, exibe a mensagem e não redireciona
    if not user:
        flash('Usuário não encontrado. Tente novamente.', 'danger')
        return redirect(url_for('esqueci_senha'))

    # Se a requisição for POST (envio do formulário)
    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        # Verifica se as senhas coincidem
        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem. Tente novamente.', 'danger')
            return redirect(url_for('recadastrar', email=email, nome=nome))

        # Atualiza a senha do usuário com bcrypt
        hashed_password = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('login'))

    # Se a requisição for GET (exibição da página inicial)
    return render_template('recadastrar.html', email=email, nome=nome)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redireciona para a página correta de acordo com o papel do usuário
        if current_user.role == 'cliente':
            return redirect(url_for('home_cliente'))
        elif current_user.role == 'prestador':
            return redirect(url_for('home_prestador'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                # Redireciona para a página correta de acordo com o papel do usuário
                if user.role == 'cliente':
                    return redirect(url_for('home_cliente'))
                elif user.role == 'prestador':
                    return redirect(url_for('home_prestador'))
            else:
                flash('Senha incorreta. Por favor, tente novamente.', 'danger')  # Mensagem de senha incorreta
        else:
            flash('Email não encontrado. Por favor, tente novamente.', 'danger')
    
    return render_template('login.html')

# Rota para home do cliente
@app.route("/home_cliente")
@login_required
@role_required('cliente')
def home_cliente():
    return render_template('homecliente.html')


# Rota para home do prestador
@app.route("/home_prestador")
@login_required
@role_required('prestador')
def home_prestador():
    return render_template('homeprestador.html')

# Rota para logout
@app.route("/logout")
def logout():
    role = current_user.role  # Verificar o papel do usuário antes de fazer o logout
    logout_user()  # Efetuar logout do usuário
    if role == 'cliente':
        return redirect(url_for('home_cliente'))  # Redirecionar para a home do cliente
    else:
        return redirect(url_for('home_prestador'))  # Redirecionar para a home do prestador

# Rota de erro 403 (acesso negado)
@app.errorhandler(403)
def forbidden_error(error):
    # Redireciona para a página apropriada com base no papel do usuário
    if current_user.is_authenticated:
        if current_user.role == 'cliente':
            return redirect(url_for('home_cliente'))
        else:
            return redirect(url_for('home_prestador'))
    return render_template('403.html'), 403

@app.route('/users')
def show_users():
    users = User.query.all()  # Recupera todos os usuários do banco de dados
    return render_template('users.html', users=users)

# Executando a aplicação


# Função para verificar as extensões permitidas


class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    descricao = db.Column(db.String(255))
    quantidade = db.Column(db.Integer, nullable=False)
    preco = db.Column(db.Float, nullable=False)
    foto = db.Column(db.String(120))  # Coluna foto adicionada
    imagem = db.Column(db.String(200), nullable=True)  # Caminho para a imagem do produto
    prestador_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Relacionamento com o prestador
    prestador = db.relationship('User', backref=db.backref('produtos', lazy=True))

    def __repr__(self):
        return f'<Produto {self.nome}>'


# Modelos
class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=True)  # Permitir telefone ser nulo

    # Relacionamento com LancamentoFinanceiro
    financeiros = db.relationship('LancamentoFinanceiro', back_populates='cliente', lazy=True)

    # Relacionamento com Pet (Adicionando backref para acessar facilmente os pets)
    pets = db.relationship('Pet', back_populates='cliente', lazy=True)

    # Relacionamento com User
    usuario = db.relationship('User', back_populates='cliente', uselist=False)

    def __repr__(self):
        return f'<Cliente {self.nome}>'



class Pet(db.Model):
    __tablename__ = 'pet'

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    idade = db.Column(db.Integer)
    sexo = db.Column(db.String(10))
    especie = db.Column(db.String(50))
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)  # A chave estrangeira não pode ser nula
    foto = db.Column(db.String(120), nullable=True)

    # Relacionamento com Cliente
    cliente = db.relationship('Cliente', back_populates='pets')

    def __repr__(self):
        return f'<Pet {self.nome}>'

# Modelo Agendamento
class Agendamento(db.Model):
    __tablename__ = 'agendamentos'
    
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))
    pet_id = db.Column(db.Integer, db.ForeignKey('pet.id'))
    especie = db.Column(db.String(50))
    servico = db.Column(db.String(50))
    data = db.Column(db.Date)
    horario = db.Column(db.Time)
    prestador = db.Column(db.String(100))

    cliente = db.relationship('Cliente', backref='agendamentos')
    pet = db.relationship('Pet', backref='agendamentos')
    
    # Relacionamento com AgendamentoProduto
    produtos = db.relationship('AgendamentoProduto', back_populates='agendamento', cascade="all, delete-orphan")

    def __init__(self, cliente_id, pet_id, especie, servico, data, horario, prestador):
        self.cliente_id = cliente_id
        self.pet_id = pet_id
        self.especie = especie
        self.servico = servico
        self.data = data
        self.horario = horario
        self.prestador = prestador

# Modelo AgendamentoProduto
class AgendamentoProduto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agendamento_id = db.Column(db.Integer, db.ForeignKey('agendamentos.id'), nullable=False)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)

    agendamento = db.relationship('Agendamento', back_populates='produtos')
    produto = db.relationship('Produto')

    def __repr__(self):
        return f'<AgendamentoProduto {self.id}>'
    
# Modelos de Financeiro
class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), nullable=False)  # Entrada ou Saída
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(250))
    data = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Transacao {self.tipo} {self.valor}>'

# Modelos de Estoque


class LancamentoFinanceiro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)  # Ex: 'Entrada' ou 'Saída'
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(255))

    cliente = db.relationship('Cliente', back_populates='financeiros')

    def __repr__(self):
        return f'<LancamentoFinanceiro {self.descricao}>'
    
#class Carrinho(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    #cliente_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #cliente = db.relationship('User', backref='carrinhos', lazy=True)
    
    # Relacionamento de itens
    #itens = db.relationship('CarrinhoItem', backref='carrinho_associado', lazy=True)  # Renomeamos o backref para 'carrinho_associado'

#class CarrinhoItem(db.Model):
   # id = db.Column(db.Integer, primary_key=True)
    #produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False)
    #produto = db.relationship('Produto', backref='carrinhos', lazy=True)
    #carrinho_id = db.Column(db.Integer, db.ForeignKey('carrinho.id'), nullable=False)  # Chave estrangeira para 'Carrinho'
    #quantidade = db.Column(db.Integer, nullable=False)

    # Relacionamento com o Carrinho (remover o backref aqui)
    #carrinho = db.relationship('Carrinho', lazy=True)  # Sem 'backref' aqui para evitar duplicação



# Obtendo os itens do carrinho do cliente atual
#carrinho_items = CarrinhoItem.query.join(Carrinho).filter(Carrinho.cliente_id == current_user.id).all()

# Exemplo de como exibir os resultados
#for item in carrinho_items:
    #print(f"Produto ID: {item.produto_id}, Quantidade: {item.quantidade}")


@app.before_request
def create_tables():
    db.create_all()

# Rotas

@app.route('/pet/<int:pet_id>')
def pet(pet_id):
    pet = Pet.query.get_or_404(pet_id)
    return jsonify({'especie': pet.especie})

@app.route('/pets_por_cliente/<int:cliente_id>')
def pets_por_cliente(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    pets = Pet.query.filter_by(cliente_id=cliente_id).all()
    pets_data = [{'id': pet.id, 'nome': pet.nome} for pet in pets]
    return jsonify({'pets': pets_data})

# Exemplo de código no seu arquivo `app.py`


@app.route('/clientes')
@login_required
def clientes():
    # Verifica se o usuário é um prestador
    if current_user.role != 'prestador':
        flash("Acesso negado! Apenas prestadores podem acessar esta página.")
        return redirect(url_for('home_cliente'))  # Redireciona para a home do cliente
    
    # Caso o usuário seja prestador, obtenha os clientes com base na role da tabela User
    usuarios_cliente = User.query.filter_by(role='cliente').all()  # Usuários com role 'cliente'
    
    # Passa a lista para o template
    return render_template('clientes.html', usuarios_cliente=usuarios_cliente)









@app.route('/adicionar_cliente', methods=['GET', 'POST'])
def adicionar_cliente():
    if request.method == 'POST':
        nome = request.form['nome']
        telefone = request.form['telefone']
        email = request.form['email']

        # Verificar se já existe um cliente com o mesmo email
        cliente_existente = Cliente.query.filter_by(email=email).first()
        if cliente_existente:
            flash('Este email já está associado a um cliente.', 'danger')
            return redirect(url_for('adicionar_cliente'))  # Redireciona para o formulário novamente

        # Criar o novo cliente
        novo_cliente = Cliente(nome=nome, telefone=telefone, email=email)
        db.session.add(novo_cliente)
        db.session.commit()

        # Criar o novo usuário associado ao cliente
        novo_usuario = User(username=email, email=email, role='cliente', cliente_id=novo_cliente.id, password='senha_segura')  # Usando uma senha genérica
        db.session.add(novo_usuario)
        db.session.commit()

        flash('Cliente adicionado com sucesso!', 'success')
        return redirect(url_for('clientes'))  # Redireciona para a página de clientes

    return render_template('adicionar_cliente.html')  # Retorna o formulário caso seja um GET




@app.route('/adicionar_pet/<int:cliente_id>', methods=['GET', 'POST'])
@login_required  # Garante que o usuário esteja autenticado
def adicionar_pet(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    if request.method == 'POST':
        nome = request.form['nome']
        idade = request.form['idade']
        sexo = request.form['sexo']
        especie = request.form['especie']
        
        # Processar a foto
        foto = None
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(foto_path)  # Salva a imagem no diretório correto
                foto = filename  # Armazena apenas o nome do arquivo no banco

        novo_pet = Pet(nome=nome, idade=idade, sexo=sexo, especie=especie, cliente_id=cliente_id, foto=foto)
        db.session.add(novo_pet)
        db.session.commit()

        # Verificar se o usuário logado é cliente ou prestador
        if current_user.is_authenticated and current_user.role == 'cliente':
            # Se for cliente, redireciona para 'meus_pets'
            return redirect(url_for('meus_pets'))
        else:
            # Se for prestador, redireciona para 'ver_pets' do cliente específico
            return redirect(url_for('ver_pets', cliente_id=cliente_id))
    
    return render_template('adicionar_pet.html', cliente=cliente)


        
@app.route('/editar_cliente/<int:id>', methods=['GET', 'POST'])
def editar_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    
    # Buscar o agendamento relacionado ao cliente, se existir
    agendamento = Agendamento.query.filter_by(cliente_id=id).first()

    if request.method == 'POST':
        cliente.nome = request.form['nome']
        cliente.telefone = request.form['telefone']
        cliente.email = request.form['email']
        db.session.commit()

        return redirect(url_for('clientes'))

    return render_template('editar_cliente.html', cliente=cliente, agendamento=agendamento)

@app.route('/remover_cliente/<int:id>', methods=['POST'])
def remover_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    
    # Lógica de remoção do cliente
    for pet in cliente.pets:
        for agendamento in pet.agendamentos:
            db.session.delete(agendamento)
        db.session.delete(pet)
    
    db.session.delete(cliente)
    db.session.commit()

    return redirect(url_for('clientes'))






@app.route('/pets')
@login_required
def pets():
    # Verifica se o usuário é um cliente
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  # Redireciona para a home do cliente
    
    # Caso o usuário seja prestador ou outro papel permitido
    pets = Pet.query.all()  # Todos os pets
    cliente = Cliente.query.first()  # Exemplo de obtenção de um cliente (altere conforme necessário)

    return render_template('pets.html', pets=pets, cliente=cliente)

@app.route('/clientes/<int:cliente_id>/pets')
def ver_pets(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    pets = Pet.query.filter_by(cliente_id=cliente_id).all()
    return render_template('ver_pets.html', cliente=cliente, pets=pets)

@app.route('/editar_pet/<int:id>', methods=['GET', 'POST'])
def editar_pet(id):
    pet = Pet.query.get_or_404(id)

    if request.method == 'POST':
        pet.nome = request.form['nome']
        pet.especie = request.form['especie']
        pet.cliente_id = request.form['cliente_id']
        
        # Verificar se há uma nova foto sendo enviada
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(foto_path)  # Salva a nova foto
                pet.foto = filename  # Atualiza o nome da foto no banco

        db.session.commit()
        
        # Verificar se o usuário é cliente ou prestador
        if current_user.role == 'cliente':
            return redirect(url_for('meus_pets'))  # Cliente vai para seus pets
        else:
            return redirect(url_for('pets'))  # Prestador vai para a lista de todos os pets

    clientes = Cliente.query.all()
    return render_template('editar_pet.html', pet=pet, clientes=clientes)

@app.route('/remover_pet/<int:id>', methods=['POST'])
@login_required
def remover_pet(id):
    pet = Pet.query.get_or_404(id)
    db.session.delete(pet)
    db.session.commit()

    # Verifica se o usuário é um cliente ou prestador
    if current_user.role == 'cliente':
        # Redireciona para "Meus Pets" se for cliente
        return redirect(url_for('meus_pets'))
    else:
        # Redireciona para a página de pets do prestador
        return redirect(url_for('pets'))


@app.route('/adicionar_agendamento', methods=['GET', 'POST'])
@login_required
def adicionar_agendamento():
    if request.method == 'POST':
        cliente_id = request.form.get('cliente_id')
        pet_id = request.form.get('pet_id')
        especie = request.form.get('especie')
        servico = request.form.get('servico')
        data = request.form.get('data')
        horario = request.form.get('horario')
        prestador = request.form.get('prestador')
        produtos_ids = request.form.getlist('produtos')
        quantidades = [int(request.form[f'quantidade_{produto_id}']) for produto_id in produtos_ids]

        if not cliente_id or not pet_id or not especie or not servico or not data or not horario or not prestador:
            return "Todos os campos são obrigatórios.", 400

        cliente = Cliente.query.get(cliente_id)
        pet = Pet.query.get(pet_id)

        if not cliente or not pet:
            return "Cliente ou Pet não encontrados.", 404

        try:
            data_formatada = datetime.strptime(data, '%Y-%m-%d').date()
            horario_formatado = datetime.strptime(horario, '%H:%M').time()
        except ValueError:
            return "Formato de data ou horário inválido.", 400

        agendamento = Agendamento(
            cliente_id=cliente_id,
            pet_id=pet_id,
            especie=especie,
            servico=servico,
            data=data_formatada,
            horario=horario_formatado,
            prestador=prestador
        )

        db.session.add(agendamento)
        db.session.commit()

        # Adicionar os produtos ao agendamento e atualizar estoque
        for i, produto_id in enumerate(produtos_ids):
            produto = Produto.query.get(produto_id)
            quantidade_usada = quantidades[i]
            
            if produto.quantidade < quantidade_usada:
                return f"Não há estoque suficiente para o produto {produto.nome}.", 400
            produto.quantidade -= quantidade_usada
            db.session.commit()

            agendamento_produto = AgendamentoProduto(
                agendamento_id=agendamento.id,
                produto_id=produto.id,
                quantidade=quantidade_usada
            )
            db.session.add(agendamento_produto)

        db.session.commit()

        # Redireciona de acordo com o papel do usuário
        if current_user.role == 'prestador':
            return redirect(url_for('agendamentos'))  # Redireciona para a página de agendamentos do prestador
        else:
            return redirect(url_for('meus_agendamentos'))  # Redireciona para a página de agendamentos do cliente

    # Carregar todos os clientes e produtos para o formulário de adição
    clientes = Cliente.query.all()
    produtos = Produto.query.all()
    return render_template('adicionar_agendamento.html', clientes=clientes, produtos=produtos)





@app.route('/agendamentos')
@login_required
def agendamentos():
    # Verifica se o usuário é um cliente
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  # Redireciona para a home do cliente
    
    # Caso o usuário seja prestador ou outro papel permitido
    agendamentos = Agendamento.query.all()  # Todos os agendamentos
    return render_template('agendamentos.html', agendamentos=agendamentos)


@app.route('/agendamentos/editar/<int:id>', methods=['GET', 'POST'])
def editar_agendamento(id):
    agendamento = Agendamento.query.get(id)
    
    if not agendamento:
        flash("Agendamento não encontrado.", "error")
        return redirect(url_for('agendamentos'))

    # Carregar clientes, pets e produtos do estoque
    clientes = Cliente.query.all()
    pets = Pet.query.all()
    produtos = Produto.query.all()

    if request.method == 'POST':
        try:
            # Atualizar os dados básicos do agendamento
            data_str = request.form.get('data', '').strip()
            if '-' in data_str:
                agendamento.data = datetime.strptime(data_str, '%Y-%m-%d').date()
            else:
                agendamento.data = datetime.strptime(data_str, '%d/%m/%Y').date()

            horario_str = request.form.get('horario', '').strip()
            agendamento.horario = datetime.strptime(horario_str, '%H:%M').time()

            agendamento.servico = request.form.get('servico', agendamento.servico)
            agendamento.prestador = request.form.get('prestador', agendamento.prestador)
            agendamento.cliente_id = request.form.get('cliente_id', agendamento.cliente_id)
            agendamento.pet_id = request.form.get('pet_id', agendamento.pet_id)

            # Produtos selecionados e suas quantidades
            produto_ids = request.form.getlist('produtos')  # IDs dos produtos
            quantidade = int(request.form.get('quantidade', 1))  # Quantidade do produto

            # Passo 1: Devolver ao estoque os produtos que estavam no agendamento
            for agendamento_produto in agendamento.produtos:
                produto = Produto.query.get(agendamento_produto.produto_id)
                if produto:
                    produto.quantidade += agendamento_produto.quantidade  # Devolver a quantidade usada
            db.session.commit()  # Commit após devolver os produtos ao estoque

            # Passo 2: Verificar se o estoque é suficiente para os novos produtos
            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    if produto.quantidade < quantidade:
                        flash(f"Estoque insuficiente para o produto {produto.nome}.", "error")
                        return redirect(url_for('editar_agendamento', id=id))

            # Passo 3: Atualizar o estoque: Subtrair a quantidade de produtos utilizados no agendamento
            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    produto.quantidade -= quantidade  # Subtrair do estoque
            db.session.commit()  # Commit após subtrair as quantidades

            # Passo 4: Limpar os produtos antigos do agendamento
            agendamento.produtos = []  # Remove todos os produtos antigos

            # Passo 5: Adicionar os novos produtos
            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    # Criar a relação de agendamento-produto com a quantidade
                    agendamento_produto = AgendamentoProduto(agendamento_id=agendamento.id, produto_id=produto.id, quantidade=quantidade)
                    agendamento.produtos.append(agendamento_produto)

            db.session.commit()  # Commit final
            flash("Agendamento atualizado com sucesso!", "success")
            return redirect(url_for('agendamentos'))

        except ValueError as e:
            flash(f"Erro na data ou horário: {e}", "error")

    return render_template('editar_agendamento.html', agendamento=agendamento, clientes=clientes, pets=pets, produtos=produtos)

@app.route('/remover_agendamento/<int:id>', methods=['GET', 'POST'])
def remover_agendamento(id):
    agendamento = Agendamento.query.get(id)
    if agendamento:
        for agendamento_produto in agendamento.produtos:
            # Atualize a quantidade de estoque do produto removido
            produto = agendamento_produto.produto
            produto.quantidade += agendamento_produto.quantidade
            db.session.commit()  # Confirme a alteração no estoque

            # Exclui a associação produto do agendamento
            db.session.delete(agendamento_produto)

        # Agora, exclui o agendamento
        db.session.delete(agendamento)
        db.session.commit()

        flash("Agendamento removido com sucesso e estoque atualizado!", "success")

        # Verificar o tipo de usuário e redirecionar para a página correta
        if current_user.role == 'cliente':  # Se for cliente
            return redirect(url_for('meus_agendamentos'))
        else:  # Se for prestador
            return redirect(url_for('agendamentos'))
    else:
        flash("Agendamento não encontrado.", "error")
        return redirect(url_for('agendamentos'))  # Redireciona para a página de agendamentos


# Rotas para Estoque
@app.route('/estoque')
@login_required
def estoque():
    # Verifica se o usuário é um cliente
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  # Redireciona para a home do cliente
    
    # Caso o usuário seja prestador ou outro papel permitido
    produtos = Produto.query.all()  # Todos os produtos no estoque
    return render_template('estoque.html', produtos=produtos)




@app.route('/adicionar_produto', methods=['GET', 'POST'])
@login_required
@role_required('prestador')  # Garante que apenas prestadores possam acessar esta rota
def adicionar_produto():
    if request.method == 'POST':
        # Receber os dados do formulário
        nome = request.form['nome']
        descricao = request.form['descricao']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        
        # Processar a foto
        foto = request.files['foto']
        foto_filename = None
        
        if foto and allowed_file(foto.filename):  # Verifica se o arquivo é permitido
            foto_filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
        
        # Criar o produto, associando o prestador logado
        novo_produto = Produto(
            nome=nome,
            descricao=descricao,
            quantidade=quantidade,
            preco=preco,
            foto=foto_filename,
            prestador_id=current_user.id  # Associa o produto ao prestador logado
        )
        
        # Salvar no banco de dados
        db.session.add(novo_produto)
        db.session.commit()
        
        flash('Produto adicionado com sucesso!', 'success')
        return redirect(url_for('estoque'))  # Redireciona para a página de estoque ou outra de sua escolha
    
    return render_template('adicionar_produto.html')


@app.route('/editar_produto/<int:id>', methods=['GET', 'POST'])
def editar_produto(id):
    produto = Produto.query.get_or_404(id)
    if request.method == 'POST':
        produto.nome = request.form['nome']
        produto.descricao = request.form['descricao']
        produto.quantidade = request.form['quantidade']
        produto.preco = request.form['preco']
        db.session.commit()
        return redirect(url_for('estoque'))  # Redireciona para a lista de produtos
    return render_template('editar_produto.html', produto=produto)


@app.route('/remover_produto/<int:id>', methods=['POST'])
def remover_produto(id):
    produto = Produto.query.get_or_404(id)
    db.session.delete(produto)
    db.session.commit()
    return redirect(url_for('estoque'))

# Rotas para Financeiro
@app.route('/financeiro')
@login_required
def financeiro():
    # Verifica se o usuário é um cliente
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  # Redireciona para a home do cliente
    
    # Caso o usuário seja prestador ou outro papel permitido
    transacoes = Transacao.query.all()  # Todas as transações financeiras
    return render_template('financeiro.html', transacoes=transacoes)

@app.route('/adicionar_transacao', methods=['GET', 'POST'])
def adicionar_transacao():
    if request.method == 'POST':
        tipo = request.form['tipo']
        valor = request.form['valor']
        descricao = request.form['descricao']
        
        nova_transacao = Transacao(tipo=tipo, valor=valor, descricao=descricao)
        db.session.add(nova_transacao)
        db.session.commit()

        return redirect(url_for('financeiro'))
    
    return render_template('adicionar_transacao.html')

@app.route('/editar_transacao/<int:id>', methods=['GET', 'POST'])
def editar_transacao(id):
    # Busca a transação pelo ID
    transacao = Transacao.query.get(id)
    if not transacao:
        return "Transação não encontrada", 404

    if request.method == 'POST':
        # Atualiza os campos com os dados enviados pelo formulário
        transacao.tipo = request.form['tipo']
        transacao.valor = request.form['valor']
        transacao.descricao = request.form['descricao']
        
        # Salva as alterações no banco de dados
        db.session.commit()
        return redirect(url_for('financeiro'))
    
    # Renderiza o formulário com os dados da transação existente
    return render_template('editar_transacao.html', transacao=transacao)

@app.route('/remover_transacao/<int:id>', methods=['POST'])
def remover_transacao(id):
    # Seu código para remover a transação, por exemplo:
    transacao = Transacao.query.get(id)
    if transacao:
        db.session.delete(transacao)
        db.session.commit()
    return redirect(url_for('financeiro'))  # Redireciona de volta para a página de transações

@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
@role_required('cliente')
def editar_perfil():
    if request.method == 'POST':
        current_user.nome = request.form['nome']
        current_user.email = request.form['email']
        db.session.commit()
        flash('Perfil atualizado com sucesso!')
        return redirect(url_for('editar_perfil'))
    
    return render_template('editar_perfil.html')

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    # Lógica para editar o usuário
    pass


@app.route('/meus_pets')
@login_required
@role_required('cliente')
def meus_pets():
    # Obtém os pets do cliente logado
    pets = Pet.query.filter_by(cliente_id=current_user.id).all()
    # Passa os pets e o cliente para o template
    return render_template('meus_pets.html', cliente=current_user, pets=pets)



@app.route('/meus_agendamentos')
@login_required
@role_required('cliente')
def meus_agendamentos():
    # Pegando os agendamentos do cliente atual
    agendamentos = Agendamento.query.filter_by(cliente_id=current_user.id).all()
    return render_template('meus_agendamentos.html', agendamentos=agendamentos)

@app.route('/loja')
@login_required
@role_required('cliente')
def loja():
    produtos = Produto.query.all()  # Obtendo todos os produtos da loja
    return render_template('loja.html', produtos=produtos)

@app.route('/adicionar_ao_carrinho/<int:produto_id>')
@login_required
@role_required('cliente')
def adicionar_ao_carrinho(produto_id):
    produto = Produto.query.get(produto_id)
    if produto:
        # Verifica se o produto já está no carrinho do cliente
        carrinho_item = CarrinhoItem.query.filter_by(cliente_id=current_user.id, produto_id=produto_id).first()
        
        if carrinho_item:
            flash(f'O produto {produto.nome} já está no seu carrinho.')
        else:
            # Adiciona o produto ao carrinho
            novo_item = CarrinhoItem(cliente_id=current_user.id, produto_id=produto_id)
            db.session.add(novo_item)
            db.session.commit()
            flash(f'O produto {produto.nome} foi adicionado ao seu carrinho!')
    else:
        flash('Produto não encontrado.')

    # Redireciona para a página do carrinho
    return redirect(url_for('meu_carrinho'))


@app.route('/meu_carrinho')
@login_required
@role_required('cliente')
def meu_carrinho():
    # Obter o carrinho do cliente logado
    carrinho_items = CarrinhoItem.query.filter_by(cliente_id=current_user.id).all()

    # Se o carrinho estiver vazio, carrinho_items será uma lista vazia
    return render_template('meu_carrinho.html', carrinho=carrinho_items)


@app.route('/remover_usuario/<int:id>')
def remover_usuario(id):
    # Lógica para remover o usuário
    return f"Usuário com ID {id} removido com sucesso!"



@app.route('/')
def home():
    return render_template('index.html')




@app.route('/perfil_cliente')
@login_required
def perfil_cliente():
    # Aqui você pode acessar as informações do cliente logado
    return render_template('perfil_cliente.html')

@app.route('/finalizar_compra', methods=['GET', 'POST'])
@login_required
@role_required('cliente')
def finalizar_compra():
    carrinho = Carrinho.query.filter_by(cliente_id=current_user.id, status='pendente').first()
    
    if request.method == 'POST':
        # Se o cliente confirmar a compra
        for item in carrinho.itens:
            produto = item.produto
            produto.quantidade -= item.quantidade  # Atualiza o estoque
            db.session.commit()  # Salva a alteração no estoque

        carrinho.status = 'finalizada'  # Marca o carrinho como finalizado
        db.session.commit()  # Salva a mudança no carrinho

        flash("Compra finalizada com sucesso!")
        return redirect(url_for('home_cliente'))  # Redireciona para a página principal do cliente ou para um resumo de compra
    
    return render_template('finalizar_compra.html', carrinho=carrinho)


@app.route('/confirmar_compra', methods=['POST'])
def confirmar_compra():
    # Código da função
    return redirect(url_for('home'))  # ou outra ação de sua escolha

@app.route('/carrinho')
@login_required
def carrinho():
    # Aqui você pode implementar a lógica para exibir os itens do carrinho
    return render_template('carrinho.html')

@app.route("/esqueci_senha", methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        nome = request.form.get('nome')  # Nome corresponde ao campo "username"
        
        # Verifique se o usuário com esse nome e email existe
        user = User.query.filter_by(email=email, username=nome).first()

        if user:
            # Redireciona para a página de recadastrar com os parâmetros de email e nome na URL
            return redirect(url_for('recadastrar', email=email, nome=nome))
        else:
            flash('Usuário não encontrado.', 'danger')
    
    return render_template('esqueci_senha.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Cria as tabelas no banco de dados
    app.run(host='0.0.0.0', port=5000)
