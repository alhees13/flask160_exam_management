from flask_session import Session
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cs50 import SQL


app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL ( "sqlite:///school.db" )

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM User WHERE id = ?", user_id)
    if user:
        return User(id=user[0]['id'], username=user[0]['username'], password=user[0]['password'], role=user[0]['role'])
    return None


# Routesss
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Get role from form
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.execute("INSERT INTO User (username, password, role) VALUES (?, ?, ?)", username, hashed_password, role)
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.execute("SELECT * FROM User WHERE username = ?", username)
        if user and check_password_hash(user[0]['password'], password):
            login_user(User(id=user[0]['id'], username=user[0]['username'], password=user[0]['password'], role=user[0]['role']))
            return redirect(url_for('home'))
        flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/create_test', methods=['GET', 'POST'])
@login_required
def create_test():
    if request.method == 'POST':
        if current_user.role != 'teacher':
            flash('Only teachers can create tests.', 'danger')
            return redirect(url_for('home'))
        test_name = request.form['test_name']
        test_description = request.form['test_description']
        db.execute("INSERT INTO Test (teacher_id, test_name, test_description) VALUES (?, ?, ?)",
                   current_user.id, test_name, test_description)
        flash('Test created successfully!', 'success')
        return redirect(url_for('manage_tests'))
    return render_template('create_test.html')

@app.route('/manage_tests')
@login_required
def manage_tests():
    tests = db.execute("SELECT * FROM Test WHERE teacher_id = ?", current_user.id)
    return render_template('manage_tests.html', tests=tests)

@app.route('/test/<int:test_id>/questions', methods=['GET', 'POST'])
@login_required
def manage_questions(test_id):
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    questions = db.execute("SELECT * FROM Question WHERE test_id = ?", test_id)
    if request.method == 'POST':
        if current_user.role != 'teacher':
            flash('Only the teacher who created the test can add questions.', 'danger')
            return redirect(url_for('home'))
        question_text = request.form['question_text']
        db.execute("INSERT INTO Question (test_id, question_text, question_type) VALUES (?, ?, 'open-ended')",
                   test_id, question_text)
        flash('Question added successfully!', 'success')
        return redirect(url_for('manage_questions', test_id=test_id))
    return render_template('manage_questions.html', test=test, questions=questions)

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    question = db.execute("SELECT * FROM Question WHERE id = ?", question_id)[0]
    test = db.execute("SELECT * FROM Test WHERE id = ?", question['test_id'])[0]
    if current_user.role != 'teacher' or current_user.id != test['teacher_id']:
        flash('Only the teacher who created the test can delete questions.', 'danger')
        return redirect(url_for('home'))
    db.execute("DELETE FROM Question WHERE id = ?", question_id)
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('manage_questions', test_id=test['id']))







@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
