import os
import re
from datetime import datetime
from functools import wraps
import pytz
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from flask import Flask, render_template, request


utc_now = datetime.now(pytz.utc)

brasilia_tz = pytz.timezone('America/Sao_Paulo')
brasilia_time = utc_now.astimezone(brasilia_tz)

formatted_time = brasilia_time.strftime('%d/%m/%Y %H:%M:%S')

app = Flask(__name__)
bcrypt = Bcrypt(app)  

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

with app.app_context():
    db.create_all() 

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='cliente')
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))  
    cliente = db.relationship('Cliente', back_populates='usuario', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)  
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este email já está em uso. Escolha outro.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nome de usuário já está em uso. Escolha outro.')

        
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user_email = User.query.filter_by(email=form.email.data).first()

        if user_email:
           
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            cliente = Cliente.query.get(user_email.cliente_id)
            if cliente:
                cliente.nome = form.username.data
                cliente.email = form.email.data
                cliente.telefone = form.telefone.data
                db.session.commit() 
            
            user_email.username = form.username.data
            user_email.password = hashed_password 
            user_email.role = form.role.data  
            db.session.commit()  

            flash('Seu cadastro foi atualizado com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login')) 
        
        else:
            
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            cliente = Cliente(nome=form.username.data, email=form.email.data, telefone=form.telefone.data)
            db.session.add(cliente)
            db.session.commit()  

            user = User(username=form.username.data, email=form.email.data, password=hashed_password, 
                        role=form.role.data, cliente_id=cliente.id)
            db.session.add(user)
            db.session.commit()

            flash('Sua conta foi criada com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login'))  
    
    return render_template('register.html', form=form)

@app.route("/recadastrar", methods=['GET', 'POST'])
def recadastrar():
    email = request.args.get('email')
    nome = request.args.get('nome')

    print(f"Email: {email}, Nome: {nome}")  

    if not email:
        flash('Email não fornecido. Tente novamente.', 'danger')
        return redirect(url_for('esqueci_senha'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Usuário não encontrado. Tente novamente.', 'danger')
        return redirect(url_for('esqueci_senha'))

    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem. Tente novamente.', 'danger')
            return redirect(url_for('recadastrar', email=email, nome=nome))

        hashed_password = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('recadastrar.html', email=email, nome=nome)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
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
                if user.role == 'cliente':
                    return redirect(url_for('home_cliente'))
                elif user.role == 'prestador':
                    return redirect(url_for('home_prestador'))
            else:
                flash('Senha incorreta. Por favor, tente novamente.', 'danger')  # Mensagem de senha incorreta
        else:
            flash('Email não encontrado. Por favor, tente novamente.', 'danger')
    
    return render_template('login.html')

@app.route("/home_cliente")
@login_required
@role_required('cliente')
def home_cliente():
    return render_template('homecliente.html')


@app.route("/home_prestador")
@login_required
@role_required('prestador')
def home_prestador():
    return render_template('homeprestador.html')

# Rota para logout
@app.route("/logout")
def logout():
    role = current_user.role  
    logout_user()  
    if role == 'cliente':
        return redirect(url_for('home_cliente'))  
    else:
        return redirect(url_for('home_prestador'))  

@app.errorhandler(403)
def forbidden_error(error):
    if current_user.is_authenticated:
        if current_user.role == 'cliente':
            return redirect(url_for('home_cliente'))
        else:
            return redirect(url_for('home_prestador'))
    return render_template('403.html'), 403

@app.route('/users')
def show_users():
    users = User.query.all()  
    return render_template('users.html', users=users)

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    descricao = db.Column(db.String(255))
    quantidade = db.Column(db.Integer, nullable=False)
    preco = db.Column(db.Float, nullable=False)
    foto = db.Column(db.String(120))  
    imagem = db.Column(db.String(200), nullable=True)  
    prestador_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    prestador = db.relationship('User', backref=db.backref('produtos', lazy=True))

    def __repr__(self):
        return f'<Produto {self.nome}>'

class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=True)  

    financeiros = db.relationship('LancamentoFinanceiro', back_populates='cliente', lazy=True)

    pets = db.relationship('Pet', back_populates='cliente', lazy=True)

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
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)  
    foto = db.Column(db.String(120), nullable=True)

    cliente = db.relationship('Cliente', back_populates='pets')

    def __repr__(self):
        return f'<Pet {self.nome}>'

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
    
    produtos = db.relationship('AgendamentoProduto', back_populates='agendamento', cascade="all, delete-orphan")

    def __init__(self, cliente_id, pet_id, especie, servico, data, horario, prestador):
        self.cliente_id = cliente_id
        self.pet_id = pet_id
        self.especie = especie
        self.servico = servico
        self.data = data
        self.horario = horario
        self.prestador = prestador

class AgendamentoProduto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agendamento_id = db.Column(db.Integer, db.ForeignKey('agendamentos.id'), nullable=False)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)

    agendamento = db.relationship('Agendamento', back_populates='produtos')
    produto = db.relationship('Produto')

    def __repr__(self):
        return f'<AgendamentoProduto {self.id}>'
    
class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), nullable=False)  
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(250))
    data = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Transacao {self.tipo} {self.valor}>'

class LancamentoFinanceiro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)  
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

@app.route('/clientes')
@login_required
def clientes():
    if current_user.role != 'prestador':
        flash("Acesso negado! Apenas prestadores podem acessar esta página.")
        return redirect(url_for('home_cliente'))  
    
    usuarios_cliente = User.query.filter_by(role='cliente').all()  
    
    return render_template('clientes.html', usuarios_cliente=usuarios_cliente)

@app.route('/adicionar_cliente', methods=['GET', 'POST'])
def adicionar_cliente():
    if request.method == 'POST':
        nome = request.form['nome']
        telefone = request.form['telefone']
        email = request.form['email']

        cliente_existente = Cliente.query.filter_by(email=email).first()
        if cliente_existente:
            flash('Este email já está associado a um cliente.', 'danger')
            return redirect(url_for('adicionar_cliente'))  

        novo_cliente = Cliente(nome=nome, telefone=telefone, email=email)
        db.session.add(novo_cliente)
        db.session.commit()

        novo_usuario = User(username=email, email=email, role='cliente', cliente_id=novo_cliente.id, password='senha_segura')  
        db.session.add(novo_usuario)
        db.session.commit()

        flash('Cliente adicionado com sucesso!', 'success')
        return redirect(url_for('clientes'))  

    return render_template('adicionar_cliente.html') 

@app.route('/adicionar_pet/<int:cliente_id>', methods=['GET', 'POST'])
@login_required  
def adicionar_pet(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    if request.method == 'POST':
        nome = request.form['nome']
        idade = request.form['idade']
        sexo = request.form['sexo']
        especie = request.form['especie']
        
        foto = None
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(foto_path)  
                foto = filename  

        novo_pet = Pet(nome=nome, idade=idade, sexo=sexo, especie=especie, cliente_id=cliente_id, foto=foto)
        db.session.add(novo_pet)
        db.session.commit()

        if current_user.is_authenticated and current_user.role == 'cliente':
            return redirect(url_for('meus_pets'))
        else:
            return redirect(url_for('ver_pets', cliente_id=cliente_id))
    
    return render_template('adicionar_pet.html', cliente=cliente)
        
@app.route('/editar_cliente/<int:id>', methods=['GET', 'POST'])
def editar_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    
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
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  
    
    pets = Pet.query.all()  
    cliente = Cliente.query.first()  

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
        
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(foto_path)  
                pet.foto = filename  

        db.session.commit()
        
        if current_user.role == 'cliente':
            return redirect(url_for('meus_pets'))  
        else:
            return redirect(url_for('pets'))  

    clientes = Cliente.query.all()
    return render_template('editar_pet.html', pet=pet, clientes=clientes)

@app.route('/remover_pet/<int:id>', methods=['POST'])
@login_required
def remover_pet(id):
    pet = Pet.query.get_or_404(id)
    db.session.delete(pet)
    db.session.commit()

    if current_user.role == 'cliente':
        return redirect(url_for('meus_pets'))
    else:
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

        if current_user.role == 'prestador':
            return redirect(url_for('agendamentos'))  # Redireciona para a página de agendamentos do prestador
        else:
            return redirect(url_for('meus_agendamentos'))  # Redireciona para a página de agendamentos do cliente

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

    clientes = Cliente.query.all()
    pets = Pet.query.all()
    produtos = Produto.query.all()

    if request.method == 'POST':
        try:
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

            produto_ids = request.form.getlist('produtos')  
            quantidade = int(request.form.get('quantidade', 1))  

            for agendamento_produto in agendamento.produtos:
                produto = Produto.query.get(agendamento_produto.produto_id)
                if produto:
                    produto.quantidade += agendamento_produto.quantidade  
            db.session.commit()  

            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    if produto.quantidade < quantidade:
                        flash(f"Estoque insuficiente para o produto {produto.nome}.", "error")
                        return redirect(url_for('editar_agendamento', id=id))

            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    produto.quantidade -= quantidade  
            db.session.commit()  

            agendamento.produtos = []  

            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    agendamento_produto = AgendamentoProduto(agendamento_id=agendamento.id, produto_id=produto.id, quantidade=quantidade)
                    agendamento.produtos.append(agendamento_produto)

            db.session.commit()  
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
            produto = agendamento_produto.produto
            produto.quantidade += agendamento_produto.quantidade
            db.session.commit()  

            db.session.delete(agendamento_produto)

        db.session.delete(agendamento)
        db.session.commit()

        flash("Agendamento removido com sucesso e estoque atualizado!", "success")

        if current_user.role == 'cliente':  
            return redirect(url_for('meus_agendamentos'))
        else:  
            return redirect(url_for('agendamentos'))
    else:
        flash("Agendamento não encontrado.", "error")
        return redirect(url_for('agendamentos'))  

@app.route('/estoque')
@login_required
def estoque():
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente')) 
    
    produtos = Produto.query.all()  
    return render_template('estoque.html', produtos=produtos)

@app.route('/adicionar_produto', methods=['GET', 'POST'])
@login_required
@role_required('prestador')  
def adicionar_produto():
    if request.method == 'POST':
        nome = request.form['nome']
        descricao = request.form['descricao']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        
        foto = request.files['foto']
        foto_filename = None
        
        if foto and allowed_file(foto.filename):  
            foto_filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
        
        novo_produto = Produto(
            nome=nome,
            descricao=descricao,
            quantidade=quantidade,
            preco=preco,
            foto=foto_filename,
            prestador_id=current_user.id  
        )
        
        db.session.add(novo_produto)
        db.session.commit()
        
        flash('Produto adicionado com sucesso!', 'success')
        return redirect(url_for('estoque'))  
    
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
        return redirect(url_for('estoque'))  
    return render_template('editar_produto.html', produto=produto)


@app.route('/remover_produto/<int:id>', methods=['POST'])
def remover_produto(id):
    produto = Produto.query.get_or_404(id)
    db.session.delete(produto)
    db.session.commit()
    return redirect(url_for('estoque'))

@app.route('/financeiro')
@login_required
def financeiro():
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  
    
    transacoes = Transacao.query.all()  
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
    transacao = Transacao.query.get(id)
    if not transacao:
        return "Transação não encontrada", 404

    if request.method == 'POST':
        transacao.tipo = request.form['tipo']
        transacao.valor = request.form['valor']
        transacao.descricao = request.form['descricao']
        
        db.session.commit()
        return redirect(url_for('financeiro'))
    
    return render_template('editar_transacao.html', transacao=transacao)

@app.route('/remover_transacao/<int:id>', methods=['POST'])
def remover_transacao(id):
    transacao = Transacao.query.get(id)
    if transacao:
        db.session.delete(transacao)
        db.session.commit()
    return redirect(url_for('financeiro'))  

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
    pass


@app.route('/meus_pets')
@login_required
@role_required('cliente')
def meus_pets():
    pets = Pet.query.filter_by(cliente_id=current_user.id).all()
    return render_template('meus_pets.html', cliente=current_user, pets=pets)



@app.route('/meus_agendamentos')
@login_required
@role_required('cliente')
def meus_agendamentos():
    agendamentos = Agendamento.query.filter_by(cliente_id=current_user.id).all()
    return render_template('meus_agendamentos.html', agendamentos=agendamentos)

@app.route('/loja')
@login_required
@role_required('cliente')
def loja():
    produtos = Produto.query.all()  
    return render_template('loja.html', produtos=produtos)

@app.route('/adicionar_ao_carrinho/<int:produto_id>')
@login_required
@role_required('cliente')
def adicionar_ao_carrinho(produto_id):
    produto = Produto.query.get(produto_id)
    if produto:
        carrinho_item = CarrinhoItem.query.filter_by(cliente_id=current_user.id, produto_id=produto_id).first()
        
        if carrinho_item:
            flash(f'O produto {produto.nome} já está no seu carrinho.')
        else:
            novo_item = CarrinhoItem(cliente_id=current_user.id, produto_id=produto_id)
            db.session.add(novo_item)
            db.session.commit()
            flash(f'O produto {produto.nome} foi adicionado ao seu carrinho!')
    else:
        flash('Produto não encontrado.')
    return redirect(url_for('meu_carrinho'))


@app.route('/meu_carrinho')
@login_required
@role_required('cliente')
def meu_carrinho():
    carrinho_items = CarrinhoItem.query.filter_by(cliente_id=current_user.id).all()
    return render_template('meu_carrinho.html', carrinho=carrinho_items)

@app.route('/remover_usuario/<int:id>')
def remover_usuario(id):
    return f"Usuário com ID {id} removido com sucesso!"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/perfil_cliente')
@login_required
def perfil_cliente():
    return render_template('perfil_cliente.html')

@app.route('/finalizar_compra', methods=['GET', 'POST'])
@login_required
@role_required('cliente')
def finalizar_compra():
    carrinho = Carrinho.query.filter_by(cliente_id=current_user.id, status='pendente').first()
    
    if request.method == 'POST':
        for item in carrinho.itens:
            produto = item.produto
            produto.quantidade -= item.quantidade  
            db.session.commit()  

        carrinho.status = 'finalizada'  
        db.session.commit()  

        flash("Compra finalizada com sucesso!")
        return redirect(url_for('home_cliente'))  
    
    return render_template('finalizar_compra.html', carrinho=carrinho)


@app.route('/confirmar_compra', methods=['POST'])
def confirmar_compra():
    return redirect(url_for('home'))  

@app.route('/carrinho')
@login_required
def carrinho():
    return render_template('carrinho.html')

@app.route("/esqueci_senha", methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        nome = request.form.get('nome')  
        
        user = User.query.filter_by(email=email, username=nome).first()

        if user:
            return redirect(url_for('recadastrar', email=email, nome=nome))
        else:
            flash('Usuário não encontrado.', 'danger')
    
    return render_template('esqueci_senha.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(host='0.0.0.0', port=5000)
