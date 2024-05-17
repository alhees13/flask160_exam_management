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


# Routessssssss
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
            if user[0]['role'] == 'teacher':
                return redirect(url_for('manage_tests'))
            elif user[0]['role'] == 'student':
                return redirect(url_for('take_test'))
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

@app.route('/edit_test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def edit_test(test_id):
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    if request.method == 'POST':
        if current_user.role != 'teacher' or current_user.id != test['teacher_id']:
            flash('Only the teacher who created the test can edit it.', 'danger')
            return redirect(url_for('home'))
        test_name = request.form['test_name']
        test_description = request.form['test_description']
        db.execute("UPDATE Test SET test_name = ?, test_description = ? WHERE id = ?",
                   test_name, test_description, test_id)
        flash('Test updated successfully!', 'success')
        return redirect(url_for('manage_tests'))
    return render_template('edit_test.html', test=test)

@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    if current_user.role != 'teacher' or current_user.id != test['teacher_id']:
        flash('Only the teacher who created the test can delete it.', 'danger')
        return redirect(url_for('home'))
    db.execute("DELETE FROM Test WHERE id = ?", test_id)
    flash('Test deleted successfully!', 'success')
    return redirect(url_for('manage_tests'))

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

@app.route('/take_test')
@login_required
def take_test():
    if current_user.role != 'student':
        flash('Only students can take tests.', 'danger')
        return redirect(url_for('home'))
    tests = db.execute("SELECT * FROM Test")
    return render_template('take_test.html', tests=tests)

@app.route('/test/<int:test_id>/take', methods=['GET', 'POST'])
@login_required
def take_specific_test(test_id):
    if current_user.role != 'student':
        flash('Only students can take tests.', 'danger')
        return redirect(url_for('home'))
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    questions = db.execute("SELECT * FROM Question WHERE test_id = ?", test_id)
    if request.method == 'POST':
        for question in questions:
            answer_text = request.form.get(f'question_{question["id"]}')
            db.execute("INSERT INTO Answer (student_id, test_id, question_id, answer_text) VALUES (?, ?, ?, ?)",
                       current_user.id, test_id, question['id'], answer_text)
        flash('Test submitted successfully!', 'success')
        return redirect(url_for('take_test'))
    return render_template('take_specific_test.html', test=test, questions=questions)

@app.route('/view_results')
@login_required
def view_results():
    if current_user.role != 'student':
        flash('Only students can view results.', 'danger')
        return redirect(url_for('home'))
    results = db.execute("SELECT * FROM Answer WHERE student_id = ?", current_user.id)
    return render_template('view_results.html', results=results)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
